import { useQuery } from "@tanstack/react-query";
import api from "src/modules/Api";

export default function useOidcConfig() {
	return useQuery({
		queryKey: ["oidcConfig"],
		queryFn: async () => {
			try {
				const response = await api.get("/oidc/config");
				return response.data;
			} catch (err) {
				return { enabled: false };
			}
		},
		retry: false,
	});
}
