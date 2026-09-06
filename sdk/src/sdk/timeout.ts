export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number | undefined,
  message: string,
  cancel?: () => void,
): Promise<T> {
  if (!timeoutMs) {
    return await promise;
  }

  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timeoutId = setTimeout(() => {
          cancel?.();
          reject(new Error(message));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  }
}
