import transitions
from transitions.extensions import GraphMachine as Machine

states = ['0', '1', '2', '3', '4', '5']
label00 = "QUIT / 221"
label01 = "USER / 331"
label02 = "PASS / 503"
label03 = "SYST / 530"
label04 = "FEAT /  EP"
label05 = "OPTS / 501"

class ProtoModel(object):
	def __init__(self, name):
		self.name = name

model = ProtoModel("Vsftpd State Expansion in Level 1")
machine = Machine(model=model, states=states, initial='0', auto_transitions=False)
machine.add_transition(label00, source = '0', dest = '0')
machine.add_transition(label01, source = '0', dest = '1')
machine.add_transition(label02, source = '0', dest = '2')
machine.add_transition(label03, source = '0', dest = '3')
machine.add_transition(label04, source = '0', dest = '4')
machine.add_transition(label05, source = '0', dest = '5')
machine.add_transition(label00, source = '1', dest = '0')
machine.add_transition(label00, source = '2', dest = '0')
machine.add_transition(label00, source = '3', dest = '0')
machine.add_transition(label00, source = '4', dest = '0')
machine.add_transition(label00, source = '5', dest = '0')

machine.model.graph.draw('a.pdf', prog='dot')