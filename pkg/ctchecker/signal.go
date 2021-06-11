package ctchecker

// interference signal
type IFSignalID uint32

// interference signal bookkeeping
type IFSingalBK uint8

const (
	IFSigNew IFSingalBK = 1 << 0
	IFSigDel IFSingalBK = 1 << 1
)

type IFSignal struct {
	ID IFSignalID
	BK IFSingalBK
}

// interference signal set
type IFSignalSet map[IFSignalID]IFSingalBK

// rawCand and rawDet should be the deterministic signal set
func GenIFSigal(rawCand, rawDet []uint32) (sList []IFSignal) {
	hashCand := map[uint32]bool{}
	hashDet := map[uint32]bool{}

	for _, s := range rawCand {
		hashCand[s] = true
	}
	for _, s := range rawDet {
		hashDet[s] = true
	}

	for _, s := range rawCand {
		if _, ok := hashDet[s]; !ok {
			sList = append(sList, IFSignal{ID: IFSignalID(s), BK: IFSigDel})
		}
	}
	for _, s := range rawDet {
		if _, ok := hashCand[s]; !ok {
			sList = append(sList, IFSignal{ID: IFSignalID(s), BK: IFSigNew})
		}
	}
	return
}

func RawSigIntersection(rawX, rawY []uint32) (is []uint32) {
	hashx := map[uint32]bool{}

	for _, s := range rawX {
		hashx[s] = true
	}

	for _, s := range rawY {
		if _, ok := hashx[s]; ok {
			is = append(is, s)
		}
	}
	return
}

func (s IFSignalSet) Merge(n []IFSignal, cnt int) (ncnt int) {
	ncnt = cnt
	for _, sig := range n {
		bk, ok := s[sig.ID]
		if !ok {
			s[sig.ID] = sig.BK
			ncnt++
		} else if ok && ((sig.BK & bk) == 0) {
			s[sig.ID] |= sig.BK
			ncnt++
		}
	}
	return
}

func (s IFSignalSet) CheckNew(n []IFSignal) bool {
	for _, sig := range n {
		bk, ok := s[sig.ID]
		if !ok {
			return true
		} else if ok && ((sig.BK & bk) == 0) {
			return true
		}
	}
	return false
}
