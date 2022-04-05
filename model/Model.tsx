interface ITrack {
    id: string;
    artist: string;
    title: string;
    uri: string;
    albumUrl: string;
    popularity: number;
}

type ChooseTrack = () => void;