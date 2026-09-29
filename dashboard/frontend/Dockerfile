# The built files are the same on every CPU, so build them once on the machine running the build
# ($BUILDPLATFORM) instead of under emulation for each image architecture: npm under ARM emulation
# is slow and can hang. Only the small nginx stage below is per-architecture.
FROM --platform=$BUILDPLATFORM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_API_BASE=""
ENV VITE_API_BASE=$VITE_API_BASE
# The brand pack in src/brand/ to build with (logo, colours, report header).
ARG VITE_BRAND=harborlight
ENV VITE_BRAND=$VITE_BRAND
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
