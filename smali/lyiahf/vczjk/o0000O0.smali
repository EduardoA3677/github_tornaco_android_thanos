.class public final Llyiahf/vczjk/o0000O0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o0000O0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 10

    iget v0, p0, Llyiahf/vczjk/o0000O0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/b65;

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/bi9;

    invoke-direct {v0, p1, v2, v1}, Llyiahf/vczjk/b65;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-ne p1, p2, :cond_1

    move-object v0, p1

    :cond_1
    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/m79;

    iget-object v1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/n79;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/m79;-><init>(Llyiahf/vczjk/n79;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/u34;->OooO0o0(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_2

    goto :goto_1

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/zr8;

    iget-object v1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/cs8;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/zr8;-><init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/yo1;)V

    new-instance v2, Llyiahf/vczjk/qr8;

    const/4 v3, 0x2

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/qr8;-><init>(Llyiahf/vczjk/cs8;I)V

    const/4 v1, 0x3

    invoke-static {p1, v0, v2, p2, v1}, Llyiahf/vczjk/dg9;->OooO0Oo(Llyiahf/vczjk/oy6;Llyiahf/vczjk/zr8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_3

    goto :goto_2

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_2
    return-object p1

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/l58;

    iget-object v1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ze3;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/l58;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/u34;->OooOo00(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_4

    goto :goto_3

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_3
    return-object p1

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/hp;

    iget-object v1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 v2, 0x5

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    const/4 v1, 0x7

    const/4 v2, 0x0

    invoke-static {p1, v2, v0, p2, v1}, Llyiahf/vczjk/dg9;->OooO0Oo(Llyiahf/vczjk/oy6;Llyiahf/vczjk/zr8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_5

    goto :goto_4

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_4
    return-object p1

    :pswitch_4
    new-instance v0, Llyiahf/vczjk/bu4;

    iget-object v1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/lm6;

    const/4 v2, 0x0

    invoke-direct {v0, p1, v1, v2}, Llyiahf/vczjk/bu4;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/lm6;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_6

    goto :goto_5

    :cond_6
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_5
    return-object p1

    :pswitch_5
    new-instance v0, Llyiahf/vczjk/hea;

    invoke-direct {v0}, Llyiahf/vczjk/hea;-><init>()V

    new-instance v4, Llyiahf/vczjk/df2;

    iget-object v1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/kf2;

    invoke-direct {v4, v2, v0}, Llyiahf/vczjk/df2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/hea;)V

    new-instance v5, Llyiahf/vczjk/cf2;

    invoke-direct {v5, v0, p1, v2}, Llyiahf/vczjk/cf2;-><init>(Llyiahf/vczjk/hea;Llyiahf/vczjk/oy6;Llyiahf/vczjk/kf2;)V

    new-instance v6, Llyiahf/vczjk/bf2;

    invoke-direct {v6, v2}, Llyiahf/vczjk/bf2;-><init>(Llyiahf/vczjk/kf2;)V

    new-instance v7, Llyiahf/vczjk/ef2;

    invoke-direct {v7, v2}, Llyiahf/vczjk/ef2;-><init>(Llyiahf/vczjk/kf2;)V

    new-instance v8, Llyiahf/vczjk/af2;

    invoke-direct {v8, v2, v0}, Llyiahf/vczjk/af2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/hea;)V

    new-instance v1, Llyiahf/vczjk/ze2;

    const/4 v9, 0x0

    move-object v3, p1

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/ze2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/oy6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_7

    goto :goto_6

    :cond_7
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_6
    return-object p1

    :pswitch_6
    move-object v3, p1

    new-instance p1, Llyiahf/vczjk/bd;

    iget-object v0, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cd;

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/bd;-><init>(Llyiahf/vczjk/cd;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, p1, p2}, Llyiahf/vczjk/u34;->OooO0o0(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_8

    goto :goto_7

    :cond_8
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_7
    return-object p1

    :pswitch_7
    move-object v3, p1

    iget-object p1, p0, Llyiahf/vczjk/o0000O0;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/o0000O0O;

    invoke-virtual {p1, v3, p2}, Llyiahf/vczjk/o0000O0O;->o00000oO(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_9

    goto :goto_8

    :cond_9
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_8
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
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
