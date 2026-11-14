import { UserButton } from "@clerk/nextjs";
import { currentUser } from "@clerk/nextjs/server";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const user = await currentUser();

  return (
    <div className="min-h-screen p-8 max-w-4xl mx-auto">
      <header className="flex items-center justify-between pb-6 border-b border-gray-200">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-gray-500">Protected workspace route</p>
        </div>
        <div className="flex items-center gap-4">
          <Link href="/" className="text-sm text-blue-600 hover:underline">
            Home
          </Link>
          <UserButton />
        </div>
      </header>

      <main className="mt-8">
        <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold mb-2">Authenticated Session</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Welcome,{" "}
            <span className="font-medium text-gray-900 dark:text-gray-100">
              {user?.firstName ?? "User"}
            </span>
            !
          </p>
          <div className="mt-4 text-xs font-mono bg-white dark:bg-black p-3 rounded border border-gray-200 dark:border-gray-700">
            <div>User ID: {user?.id}</div>
            <div>Email: {user?.emailAddresses[0]?.emailAddress ?? "N/A"}</div>
          </div>
        </div>
      </main>
    </div>
  );
}
