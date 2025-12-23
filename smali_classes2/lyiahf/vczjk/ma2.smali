.class public final synthetic Llyiahf/vczjk/ma2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ma2;->OooOOO0:I

    iput-object p3, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    iput p1, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;III)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/ma2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    iput p2, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ma2;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p2, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/br6;->OooO0o0(Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p2, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/thanos/process/v2/RunningService;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/mt6;->OooO0oO(Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p2, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ltornaco/apps/thanox/running/RunningService;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/ht6;->OooO0o(Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p2, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yg5;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/rs;->OooO0Oo(Llyiahf/vczjk/yg5;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/kl5;

    iget v1, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    invoke-static {v1, p2, p1, v0}, Llyiahf/vczjk/m6a;->OooOO0o(IILlyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p2, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/m6a;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/ma2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/w41;

    iget v1, p0, Llyiahf/vczjk/ma2;->OooOOO:I

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/zsa;->OooO0o(Llyiahf/vczjk/w41;ILlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

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
