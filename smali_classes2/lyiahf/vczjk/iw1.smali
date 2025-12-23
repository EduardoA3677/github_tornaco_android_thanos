.class public final synthetic Llyiahf/vczjk/iw1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/lw1;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/lw1;Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/iw1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/iw1;->OooOOO:Llyiahf/vczjk/lw1;

    iput-object p2, p0, Llyiahf/vczjk/iw1;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/iw1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x6a;

    iget-object v1, v0, Llyiahf/vczjk/x6a;->OooO00o:Llyiahf/vczjk/w6a;

    float-to-int p1, p1

    int-to-long v2, p1

    const-wide/16 v4, 0x3e8

    mul-long v6, v2, v4

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/16 v8, 0xf

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/w6a;->OooO00o(Llyiahf/vczjk/w6a;FIIIJI)Llyiahf/vczjk/w6a;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOO:Llyiahf/vczjk/lw1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lw1;->OooO0o0(Llyiahf/vczjk/w6a;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x6a;

    iget-object v1, v0, Llyiahf/vczjk/x6a;->OooO00o:Llyiahf/vczjk/w6a;

    float-to-int v5, p1

    const/4 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/16 v8, 0x17

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/w6a;->OooO00o(Llyiahf/vczjk/w6a;FIIIJI)Llyiahf/vczjk/w6a;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOO:Llyiahf/vczjk/lw1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lw1;->OooO0o0(Llyiahf/vczjk/w6a;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result v1

    iget-object p1, p0, Llyiahf/vczjk/iw1;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/x6a;

    iget-object v0, p1, Llyiahf/vczjk/x6a;->OooO00o:Llyiahf/vczjk/w6a;

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/16 v7, 0x1e

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/w6a;->OooO00o(Llyiahf/vczjk/w6a;FIIIJI)Llyiahf/vczjk/w6a;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOO:Llyiahf/vczjk/lw1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lw1;->OooO0o0(Llyiahf/vczjk/w6a;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result v3

    iget-object p1, p0, Llyiahf/vczjk/iw1;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/x6a;

    iget-object v0, p1, Llyiahf/vczjk/x6a;->OooO00o:Llyiahf/vczjk/w6a;

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/16 v7, 0x1b

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/w6a;->OooO00o(Llyiahf/vczjk/w6a;FIIIJI)Llyiahf/vczjk/w6a;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOO:Llyiahf/vczjk/lw1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lw1;->OooO0o0(Llyiahf/vczjk/w6a;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_3
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result v2

    iget-object p1, p0, Llyiahf/vczjk/iw1;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/x6a;

    iget-object v0, p1, Llyiahf/vczjk/x6a;->OooO00o:Llyiahf/vczjk/w6a;

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v1, 0x0

    const/4 v3, 0x0

    const/16 v7, 0x1d

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/w6a;->OooO00o(Llyiahf/vczjk/w6a;FIIIJI)Llyiahf/vczjk/w6a;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/iw1;->OooOOO:Llyiahf/vczjk/lw1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lw1;->OooO0o0(Llyiahf/vczjk/w6a;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
