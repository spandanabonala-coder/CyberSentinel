FROM gcc:13
WORKDIR /app
COPY . .
RUN gcc -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra server.c url_detection.c log_analysis.c stack.c queue.c bst.c -o cybersentinel
ENV PORT=10000
EXPOSE 10000
CMD ["./cybersentinel"]
