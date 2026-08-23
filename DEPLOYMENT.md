# Backend Deployment Guide (Standalone Host)

This `backend/` folder is **100% self-contained** and can be deployed independently to any cloud hosting platform (such as [Render](https://render.com), [Railway](https://railway.app), [Fly.io](https://fly.io), [AWS Elastic Beanstalk](https://aws.amazon.com/elasticbeanstalk/), or [Heroku](https://heroku.com)).

---

## 📁 Files Included in `backend/`
```
backend/
├── types/
│   └── index.ts        # Fully self-contained TypeScript interfaces
├── .env.example        # Production environment template
├── .env                # Local development environment
├── package.json        # Dependencies & deployment scripts
├── server.ts           # Complete Express + MongoDB + JWT API server
├── seed.js             # Initial database seeder (42 faculty, 5 depts, 3 devices)
└── tsconfig.json       # Independent TypeScript configuration
```

---

## ⚙️ Required Environment Variables on Your Host

Configure these environment variables in your hosting provider's dashboard:

| Variable | Description | Example Production Value |
| :--- | :--- | :--- |
| `NODE_ENV` | Application environment | `production` |
| `PORT` | Server listening port | `3000` *(usually auto-set by host)* |
| `MONGODB_URI` | MongoDB Atlas Cloud Connection String | `mongodb+srv://admin:pass@cluster.mongodb.net/elswedy_attendance?retryWrites=true&w=majority` |
| `CORS_ORIGIN` | Allowed Frontend Domain URL(s) | `https://your-frontend.vercel.app` |
| `JWT_SECRET` | 256-bit cryptographic secret | `xK9mP2vL7nQ4wR8jF3hT6yB1cA5dG0eU9sN2oI7kM4pW8xZ3qJ6rV1tY5uH0b` |
| `JWT_EXPIRY` | JWT Token Expiry Duration | `8h` |

---

## 🚀 Deployment Steps (Example: Render / Railway)

1. **Upload / Connect Repository**: Point your host service to the `backend/` directory (or push only this folder to your backend Git repository).
2. **Build Command**:
   ```bash
   npm install
   ```
3. **Start Command**:
   ```bash
   npx tsx server.ts
   ```
4. **Health Check URL**:
   Your host can monitor server health using the built-in endpoint:
   ```
   GET /health  (or GET /api/health)
   ```
5. **(Optional) Database Seeding**:
   If connecting to a brand-new MongoDB cluster, seed the initial database once:
   ```bash
   node seed.js
   ```
