.class public final synthetic Llyiahf/vczjk/wz;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/wz;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    iput p5, p0, Llyiahf/vczjk/wz;->OooOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;II)V
    .locals 0

    const/4 p5, 0x1

    iput p5, p0, Llyiahf/vczjk/wz;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    iput p6, p0, Llyiahf/vczjk/wz;->OooOOO:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Llyiahf/vczjk/hl5;ILlyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;I)V
    .locals 0

    const/4 p6, 0x2

    iput p6, p0, Llyiahf/vczjk/wz;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/wz;->OooOOO:I

    iput-object p4, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/wz;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p1, p0, Llyiahf/vczjk/wz;->OooOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/qs5;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/oy7;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Lnow/fortuitous/thanos/process/v2/RunningProcessState;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/le3;

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/mt6;->OooO0O0(Llyiahf/vczjk/qs5;Llyiahf/vczjk/oy7;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rn9;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/hl5;

    iget v2, p0, Llyiahf/vczjk/wz;->OooOOO:I

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/v34;->OooOO0(Ljava/lang/String;Llyiahf/vczjk/hl5;ILlyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x7

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/le3;

    iget v6, p0, Llyiahf/vczjk/wz;->OooOOO:I

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Ljava/lang/String;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/dn8;->OooOo0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/wz;->OooOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/j00;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/o4;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/en1;

    iget-object p1, p0, Llyiahf/vczjk/wz;->OooOOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/yi4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/j00;Llyiahf/vczjk/o4;Llyiahf/vczjk/en1;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
