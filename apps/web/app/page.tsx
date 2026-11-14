import { auth } from "@clerk/nextjs/server";
import { UserButton, SignInButton, SignUpButton } from "@clerk/nextjs";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function Home() {
  const { userId } = await auth();

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-8 text-center bg-zinc-950 text-zinc-100">
      <header className="absolute top-6 right-8 flex items-center gap-4">
        {userId ? (
          <>
            <Link
              href="/dashboard"
              className="text-sm font-medium text-blue-400 hover:underline mr-2"
            >
              Dashboard
            </Link>
            <UserButton />
          </>
        ) : (
          <>
            <SignInButton mode="modal">
              <button className="px-4 py-2 text-sm font-medium rounded-md bg-white text-zinc-900 hover:opacity-90">
                Sign In
              </button>
            </SignInButton>
            <SignUpButton mode="modal">
              <button className="px-4 py-2 text-sm font-medium rounded-md border border-zinc-700 hover:bg-zinc-800">
                Sign Up
              </button>
            </SignUpButton>
          </>
        )}
      </header>

      <main className="max-w-xl space-y-6">
        <h1 className="text-4xl font-extrabold tracking-tight">AI Platform</h1>
        <p className="text-zinc-400 text-lg">
          Clerk authentication is fully configured. Sign in or sign up to access your protected workspace.
        </p>

        <div className="flex gap-4 justify-center pt-4">
          {userId ? (
            <Link
              href="/dashboard"
              className="px-6 py-3 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700"
            >
              Open Dashboard &rarr;
            </Link>
          ) : (
            <SignInButton mode="modal">
              <button className="px-6 py-3 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700">
                Get Started
              </button>
            </SignInButton>
          )}
        </div>
      </main>
    </div>
  );
}
