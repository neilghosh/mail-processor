"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const datastore_1 = require("@google-cloud/datastore");
const googleapis_1 = require("googleapis");
const crypto_1 = require("./utils/crypto");
require("dotenv/config");
const app = (0, express_1.default)();
const port = process.env.PORT || 8080;
app.use(express_1.default.static('public'));
// Route to start the Google authentication flow
app.get('/auth/google', (req, res) => {
    // Dynamically construct the redirect URI based on the request
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
    const oauth2Client = new googleapis_1.google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri // Use the dynamic URI
    );
    const scopes = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ];
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes
    });
    res.redirect(url);
});
// The callback route that Google redirects to
app.get('/auth/google/callback', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // THE FIX: Also use the dynamic redirect URI here
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
    const oauth2Client = new googleapis_1.google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri // Use the dynamic URI to match the initial request
    );
    const { code } = req.query;
    try {
        const { tokens } = yield oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const oauth2 = googleapis_1.google.oauth2({
            auth: oauth2Client,
            version: 'v2'
        });
        const { data } = yield oauth2.userinfo.get();
        const datastore = new datastore_1.Datastore();
        const kind = 'User';
        const userKey = datastore.key([kind, data.id]);
        const user = {
            key: userKey,
            data: {
                google_id: data.id,
                email: data.email,
                refreshToken: tokens.refresh_token ? (0, crypto_1.encrypt)(tokens.refresh_token) : null,
                createdAt: new Date()
            }
        };
        yield datastore.save(user);
        res.send('Authentication successful! You can close this tab.');
    }
    catch (error) {
        console.error('Error during Google auth callback:', error);
        res.status(500).send('Authentication failed. Please check the server logs for more details.');
    }
}));
app.post('/api/tasks/process-emails', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // Add authentication for Cloud Scheduler
    const datastore = new datastore_1.Datastore();
    const query = datastore.createQuery('User');
    const [users] = yield datastore.runQuery(query);
    for (const user of users) {
        const oauth2Client = new googleapis_1.google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
        const refreshToken = (0, crypto_1.decrypt)(user.refreshToken);
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const { token } = yield oauth2Client.getAccessToken();
        oauth2Client.setCredentials({ access_token: token });
        const gmail = googleapis_1.google.gmail({ version: 'v1', auth: oauth2Client });
        const response = yield gmail.users.messages.list({
            userId: 'me',
            q: 'is:unread in:inbox after:' + new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().substring(0, 10)
        });
        const newEmailCount = response.data.resultSizeEstimate || 0;
        const emailStat = {
            key: datastore.key('EmailStat'),
            data: {
                userId: user[datastore.KEY],
                newEmailCount: newEmailCount,
                processedAt: new Date()
            }
        };
        yield datastore.save(emailStat);
    }
    res.status(200).send('Email processing complete.');
}));
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
