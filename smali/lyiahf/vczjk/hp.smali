.class public final synthetic Llyiahf/vczjk/hp;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/le3;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/hp;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/hp;->OooOOO:Llyiahf/vczjk/le3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    const-string v0, "it"

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v2, p0, Llyiahf/vczjk/hp;->OooOOO:Llyiahf/vczjk/le3;

    iget v3, p0, Llyiahf/vczjk/hp;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-object v1

    :pswitch_1
    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    check-cast v0, Ljava/lang/Float;

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    move-result v0

    goto :goto_1

    :cond_1
    move v0, v2

    :goto_1
    new-instance v3, Llyiahf/vczjk/m01;

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/m01;-><init>(FF)V

    new-instance v2, Llyiahf/vczjk/o97;

    const/4 v4, 0x0

    invoke-direct {v2, v0, v3, v4}, Llyiahf/vczjk/o97;-><init>(FLlyiahf/vczjk/n01;I)V

    sget-object v0, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/ve8;->OooO0OO:Llyiahf/vczjk/ze8;

    sget-object v3, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v4, 0x1

    aget-object v3, v3, v4

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-object v1

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/p86;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-object v1

    :pswitch_5
    check-cast p1, Ljava/lang/Throwable;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-object v1

    :pswitch_6
    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/hg2;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n21;

    iget-wide v4, p1, Llyiahf/vczjk/n21;->OooO00o:J

    const/4 v11, 0x0

    const/4 v12, 0x0

    const-wide/16 v6, 0x0

    const-wide/16 v8, 0x0

    const/4 v10, 0x0

    const/16 v13, 0x7e

    invoke-static/range {v3 .. v13}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    return-object v1

    :pswitch_7
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-object v1

    :pswitch_8
    check-cast p1, Llyiahf/vczjk/ft7;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO00o(F)V

    return-object v1

    :pswitch_9
    check-cast p1, Llyiahf/vczjk/ft7;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO00o(F)V

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
