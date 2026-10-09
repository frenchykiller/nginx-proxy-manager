import { useQuery } from "@tanstack/react-query";

export default function useOidcConfig() {
	return useQuery({
		queryKey: ["oidcConfig"],
		queryFn: async () => {
			try {
				const response = await fetch("/api/oidc/config");
				return await response.json();
			} catch (err) {
				return { enabled: false };
			}
		},
		retry: false,
	});
}
