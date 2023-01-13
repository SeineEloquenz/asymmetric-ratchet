// The node name representation was chosen to be in line with the notation used in the paper:
// In the paper 'w0' and 'w1' are the children of the node 'w', here we have 'self.1 << 1' and
// '(self.1 << 1) | 1'. This makes it easier to follow along.
use arrayvec::ArrayVec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeName(u8, u32);

impl NodeName {
    pub const ROOT: Self = NodeName(0, 0);
    pub const MAX: Self = NodeName(32, u32::MAX);

    fn canonicalized(mut self) -> NodeName {
        let mut mask = u32::MAX;
        for i in self.0..32 {
            mask ^= 1 << i;
        }
        self.1 &= mask;
        self
    }

    pub fn new(length: u8, path: u32) -> Self {
        assert!(length <= 32);
        NodeName(length, path).canonicalized()
    }

    pub fn parent(self) -> NodeName {
        assert!(self.0 > 0);
        NodeName(self.0 - 1, self.1 >> 1)
    }

    pub fn left(self) -> NodeName {
        assert!(self.0 < 32);
        NodeName(self.0 + 1, self.1 << 1)
    }

    pub fn right(self) -> NodeName {
        assert!(self.0 < 32);
        NodeName(self.0 + 1, (self.1 << 1) | 1)
    }

    pub fn next(mut self) -> Option<NodeName> {
        if self == NodeName::MAX {
            None
        } else {
            if self.len() < 32 {
                self = self.left()
            } else {
                while self == self.parent().right() {
                    self = self.parent();
                }
                self = self.parent().right();
            }
            Some(self)
        }
    }

    pub fn len(self) -> u8 {
        self.0
    }

    pub fn path(self) -> u32 {
        self.1
    }

    pub fn is_leaf(self) -> bool {
        self.0 == 32
    }

    pub fn walk(mut self) -> impl Iterator<Item = NodeName> {
        let mut parents = ArrayVec::<NodeName, 32>::new();
        while self.len() > 0 {
            parents.push(self);
            self = self.parent();
        }
        parents.reverse();
        parents.into_iter()
    }

    pub fn from_numbering(mut number: u64) -> NodeName {
        // Number of nodes: 2**33 - 1
        assert!(number < 2u64.pow(33) - 1);
        let mut node = NodeName::ROOT;
        let mut cutoff = 2u64.pow(32);
        while cutoff > 0 {
            if number == 0 {
                return node;
            } else if number >= cutoff {
                node = node.right();
                number -= cutoff;
            } else {
                node = node.left();
                number -= 1;
            }
            cutoff = cutoff / 2;
        }
        node
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_numbering_root() {
        assert_eq!(NodeName::from_numbering(0), NodeName::ROOT);
    }

    #[test]
    fn from_numbering_node() {
        assert_eq!(
            NodeName::from_numbering(2u64.pow(32) + 1),
            NodeName::ROOT.right().left()
        );
    }
}
