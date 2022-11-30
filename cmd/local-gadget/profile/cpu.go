// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package profile

import (
	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/profile"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

type CPUParser struct {
	commonutils.GadgetParser[types.Report]
	commonutils.OutputConfig
	cpuFlags *commonprofile.CPUFlags
}

func newCPUCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var cpuFlags commonprofile.CPUFlags

	runCmd := func(*cobra.Command, []string) error {
		if cpuFlags.ProfileUserOnly && cpuFlags.ProfileKernelOnly {
			return commonutils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
		}

		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, types.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		profileGadget := &ProfileGadget[types.Report]{
			commonFlags: &commonFlags,
			parser: &commonprofile.CPUParser{
				GadgetParser: *parser,
				OutputConfig: commonFlags.OutputConfig,
				CPUFlags:     &cpuFlags,
			},
			inProgressMsg: "Capturing stack traces",
			createAndRunTracer: func(mountnsmap *ebpf.Map, enricher gadgets.DataEnricher) (profile.Tracer, error) {
				return tracer.NewTracer(enricher, &tracer.Config{
					MountnsMap:      mountnsmap,
					UserStackOnly:   cpuFlags.ProfileUserOnly,
					KernelStackOnly: cpuFlags.ProfileKernelOnly,
				})
			},
		}

		return profileGadget.Run()
	}

	cmd := commonprofile.NewCPUCmd(runCmd, &cpuFlags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}