.class public final synthetic Llyiahf/vczjk/rt;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/kl5;II)V
    .locals 0

    const/4 p3, 0x1

    iput p3, p0, Llyiahf/vczjk/rt;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rt;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/rt;->OooOOO:Ljava/lang/Object;

    iput p4, p0, Llyiahf/vczjk/rt;->OooOOOO:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/rt;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/rt;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/rt;->OooOOOo:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/rt;->OooOOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/gt8;Llyiahf/vczjk/kl5;I)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Llyiahf/vczjk/rt;->OooOOO0:I

    sget-object v0, Llyiahf/vczjk/zc1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rt;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/rt;->OooOOO:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/rt;->OooOOOO:I

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;ILlyiahf/vczjk/le3;I)V
    .locals 0

    const/4 p4, 0x2

    iput p4, p0, Llyiahf/vczjk/rt;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rt;->OooOOO:Ljava/lang/Object;

    iput p2, p0, Llyiahf/vczjk/rt;->OooOOOO:I

    iput-object p3, p0, Llyiahf/vczjk/rt;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    const/4 v0, 0x1

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v2, p0, Llyiahf/vczjk/rt;->OooOOO:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/rt;->OooOOOo:Ljava/lang/Object;

    iget v4, p0, Llyiahf/vczjk/rt;->OooOOOO:I

    iget v5, p0, Llyiahf/vczjk/rt;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    packed-switch v5, :pswitch_data_0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    or-int/lit8 p2, v4, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Llyiahf/vczjk/a91;

    check-cast v2, Llyiahf/vczjk/rn9;

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/gm9;->OooO00o(Llyiahf/vczjk/rn9;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v1

    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    or-int/lit8 p2, v4, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Llyiahf/vczjk/ur0;

    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/er8;->OooO0OO(Llyiahf/vczjk/ur0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v1

    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    or-int/lit8 p2, v4, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Llyiahf/vczjk/kl5;

    sget-object v0, Llyiahf/vczjk/zc1;->OooO00o:Llyiahf/vczjk/a91;

    check-cast v3, Llyiahf/vczjk/gt8;

    invoke-static {v3, v2, p1, p2}, Llyiahf/vczjk/br6;->OooO0Oo(Llyiahf/vczjk/gt8;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V

    return-object v1

    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    or-int/lit8 p2, v4, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Ljava/lang/String;

    check-cast v3, Llyiahf/vczjk/le3;

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/fu6;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v1

    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x7

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Llyiahf/vczjk/le3;

    check-cast v2, Llyiahf/vczjk/kl5;

    invoke-static {v2, v4, v3, p1, p2}, Llyiahf/vczjk/m6a;->OooO0o0(Llyiahf/vczjk/kl5;ILlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v1

    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Llyiahf/vczjk/kl5;

    check-cast v3, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    invoke-static {v3, v2, p1, p2, v4}, Llyiahf/vczjk/zsa;->OooO0oo(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;II)V

    return-object v1

    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    or-int/lit8 p2, v4, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v2, Llyiahf/vczjk/kl5;

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
