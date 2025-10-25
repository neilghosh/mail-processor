
import express from 'express';
import { Datastore } from '@google-cloud/datastore';
import { google } from 'googleapis';
import { encrypt, decrypt } from './utils/crypto';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 8080;

// Trust the proxy to get the correct protocol (http vs https)
app.set('trust proxy', 1);

app.use(express.static('public'));

// Hardcoded redirect URI. This may need to be updated if the environment changes.
const redirectUri = 'https://8080-firebase-mail-processor-1761408049913.cluster-edb2jv34dnhjisxuq5m7l37ccy.cloudworkstations.dev/auth/google/callback';

// Route to start the Google authentication flow
app.get('/auth/google', (req, res) => {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        redirectUri
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
app.get('/auth/google/callback', async (req, res) => {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        redirectUri
    );

    const { code } = req.query;

    try {
        const { tokens } = await oauth2Client.getToken(code as string);
        oauth2Client.setCredentials(tokens);

        const oauth2 = google.oauth2({
            auth: oauth2Client,
            version: 'v2'
        });

        const { data } = await oauth2.userinfo.get();

        const datastore = new Datastore();
        const kind = 'User';
        const userKey = datastore.key([kind, data.id!]);
        const user = {
            key: userKey,
            data: {
                google_id: data.id,
                email: data.email,
                refreshToken: tokens.refresh_token ? encrypt(tokens.refresh_token) : null,
                createdAt: new Date()
            }
        };

        await datastore.save(user);

        res.send('Authentication successful! You can close this tab.');
    } catch (error) {
        console.error('Error during Google auth callback:', error);
        res.status(500).send('Authentication failed. Please check the server logs for more details.');
    }
});

app.post('/api/tasks/process-emails', async (req, res) => {
    // Add authentication for Cloud Scheduler
    const datastore = new Datastore();
    const query = datastore.createQuery('User');
    const [users] = await datastore.runQuery(query);

    for (const user of users) {
        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );

        const refreshToken = decrypt(user.refreshToken);
        oauth2Client.setCredentials({ refresh_token: refreshToken });

        const { token } = await oauth2Client.getAccessToken();
        oauth2Client.setCredentials({ access_token: token });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const response = await gmail.users.messages.list({
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

        await datastore.save(emailStat);
    }

    res.status(200).send('Email processing complete.');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
