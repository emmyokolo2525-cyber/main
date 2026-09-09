FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .

# Accept Vite environment variables at build time so the static bundle is
# compiled with the correct runtime values baked in.  All four are optional so
# the image still builds successfully for local development without them.
ARG VITE_API_BASE
ARG VITE_STELLAR_RPC_URL
ARG VITE_STELLAR_READONLY_SOURCE
ARG VITE_HARPOCRATES_REGISTRY_ID

ENV VITE_API_BASE=$VITE_API_BASE \
    VITE_STELLAR_RPC_URL=$VITE_STELLAR_RPC_URL \
    VITE_STELLAR_READONLY_SOURCE=$VITE_STELLAR_READONLY_SOURCE \
    VITE_HARPOCRATES_REGISTRY_ID=$VITE_HARPOCRATES_REGISTRY_ID

RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
