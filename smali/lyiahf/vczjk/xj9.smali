.class public final Llyiahf/vczjk/xj9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bi9;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/mk9;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/mk9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final OooO()V
    .locals 0

    return-void
.end method

.method private final OooO0o()V
    .locals 0

    return-void
.end method

.method private final OooO0o0()V
    .locals 0

    return-void
.end method

.method private final OooO0oO()V
    .locals 0

    return-void
.end method


# virtual methods
.method public final OooO00o(J)V
    .locals 11

    iget v0, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v1, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOO0O()Z

    move-result v0

    if-eqz v0, :cond_5

    iget-object v0, v1, Llyiahf/vczjk/mk9;->OooOOo:Llyiahf/vczjk/qs5;

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tl3;

    if-eqz v2, :cond_0

    goto/16 :goto_1

    :cond_0
    sget-object v2, Llyiahf/vczjk/tl3;->OooOOOO:Llyiahf/vczjk/tl3;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const/4 v0, -0x1

    iput v0, v1, Llyiahf/vczjk/mk9;->OooOo00:I

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO()V

    iget-object v0, v1, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/nm9;->OooO0OO(J)Z

    move-result v0

    if-ne v0, v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v0, v0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_1

    goto/16 :goto_1

    :cond_1
    invoke-virtual {v1, v3}, Llyiahf/vczjk/mk9;->OooO0oo(Z)V

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    sget-wide v2, Llyiahf/vczjk/gn9;->OooO0O0:J

    const/4 v4, 0x5

    const/4 v5, 0x0

    invoke-static {v0, v5, v2, v3, v4}, Llyiahf/vczjk/gl9;->OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/an;JI)Llyiahf/vczjk/gl9;

    move-result-object v2

    sget-object v7, Llyiahf/vczjk/e86;->OooOo00:Llyiahf/vczjk/yz2;

    const/4 v5, 0x1

    const/4 v6, 0x0

    const/4 v8, 0x1

    move-wide v3, p1

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/mk9;->OooO0OO(Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;JZZLlyiahf/vczjk/md8;Z)J

    move-result-wide p1

    move-wide v9, v3

    move-object v4, v1

    move-wide v0, v9

    const/16 v2, 0x20

    shr-long/2addr p1, v2

    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iput-object p1, v4, Llyiahf/vczjk/mk9;->OooOOOo:Ljava/lang/Integer;

    goto :goto_0

    :cond_2
    move-object v4, v1

    move-wide v0, p1

    iget-object p1, v4, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-eqz p1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object p1

    if-eqz p1, :cond_4

    invoke-virtual {p1, v0, v1, v2}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result p1

    iget-object p2, v4, Llyiahf/vczjk/mk9;->OooO0O0:Llyiahf/vczjk/s86;

    invoke-interface {p2, p1}, Llyiahf/vczjk/s86;->OooO0o0(I)I

    move-result p1

    invoke-virtual {v4}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object p2

    iget-object p2, p2, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    invoke-static {p1, p1}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide v5

    invoke-static {p2, v5, v6}, Llyiahf/vczjk/mk9;->OooO0o0(Llyiahf/vczjk/an;J)Llyiahf/vczjk/gl9;

    move-result-object p1

    invoke-virtual {v4, v3}, Llyiahf/vczjk/mk9;->OooO0oo(Z)V

    iget-object p2, v4, Llyiahf/vczjk/mk9;->OooOO0O:Llyiahf/vczjk/jm3;

    if-eqz p2, :cond_3

    const/16 v2, 0x9

    invoke-interface {p2, v2}, Llyiahf/vczjk/jm3;->OooO00o(I)V

    :cond_3
    iget-object p2, v4, Llyiahf/vczjk/mk9;->OooO0OO:Llyiahf/vczjk/rm4;

    invoke-interface {p2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_4
    :goto_0
    sget-object p1, Llyiahf/vczjk/vl3;->OooOOO0:Llyiahf/vczjk/vl3;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/mk9;->OooOOo0(Llyiahf/vczjk/vl3;)V

    iput-wide v0, v4, Llyiahf/vczjk/mk9;->OooOOOO:J

    new-instance p1, Llyiahf/vczjk/p86;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    iget-object p2, v4, Llyiahf/vczjk/mk9;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const-wide/16 p1, 0x0

    iput-wide p1, v4, Llyiahf/vczjk/mk9;->OooOOo0:J

    :cond_5
    :goto_1
    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mk9;->OooOO0o(Z)J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/zd8;->OooO00o(J)J

    move-result-wide v0

    iget-object p2, p1, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-eqz p2, :cond_7

    invoke-virtual {p2}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object p2

    if-nez p2, :cond_6

    goto :goto_2

    :cond_6
    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/nm9;->OooO0o0(J)J

    move-result-wide v0

    iput-wide v0, p1, Llyiahf/vczjk/mk9;->OooOOOO:J

    new-instance p2, Llyiahf/vczjk/p86;

    invoke-direct {p2, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    iget-object v0, p1, Llyiahf/vczjk/mk9;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const-wide/16 v0, 0x0

    iput-wide v0, p1, Llyiahf/vczjk/mk9;->OooOOo0:J

    sget-object p2, Llyiahf/vczjk/tl3;->OooOOO0:Llyiahf/vczjk/tl3;

    iget-object v0, p1, Llyiahf/vczjk/mk9;->OooOOo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mk9;->OooOOoo(Z)V

    :cond_7
    :goto_2
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/mk9;->OooO0O0(Llyiahf/vczjk/mk9;Llyiahf/vczjk/tl3;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/mk9;->OooO00o(Llyiahf/vczjk/mk9;Llyiahf/vczjk/p86;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    return-void
.end method

.method public final OooO0Oo(J)V
    .locals 10

    const/4 v0, 0x1

    iget v1, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    packed-switch v1, :pswitch_data_0

    iget-object v2, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOO0O()Z

    move-result v1

    if-eqz v1, :cond_6

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-nez v1, :cond_0

    goto/16 :goto_2

    :cond_0
    iget-wide v3, v2, Llyiahf/vczjk/mk9;->OooOOo0:J

    invoke-static {v3, v4, p1, p2}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide p1

    iput-wide p1, v2, Llyiahf/vczjk/mk9;->OooOOo0:J

    iget-object p1, v2, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    const/4 p2, 0x0

    if-eqz p1, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object p1

    if-eqz p1, :cond_5

    iget-wide v3, v2, Llyiahf/vczjk/mk9;->OooOOOO:J

    iget-wide v5, v2, Llyiahf/vczjk/mk9;->OooOOo0:J

    invoke-static {v3, v4, v5, v6}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v3

    new-instance v1, Llyiahf/vczjk/p86;

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/p86;-><init>(J)V

    iget-object v3, v2, Llyiahf/vczjk/mk9;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v1, v2, Llyiahf/vczjk/mk9;->OooOOOo:Ljava/lang/Integer;

    sget-object v8, Llyiahf/vczjk/e86;->OooOo00:Llyiahf/vczjk/yz2;

    if-nez v1, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooO()Llyiahf/vczjk/p86;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v3, v1, Llyiahf/vczjk/p86;->OooO00o:J

    invoke-virtual {p1, v3, v4}, Llyiahf/vczjk/nm9;->OooO0OO(J)Z

    move-result v1

    if-nez v1, :cond_2

    iget-object v1, v2, Llyiahf/vczjk/mk9;->OooO0O0:Llyiahf/vczjk/s86;

    iget-wide v3, v2, Llyiahf/vczjk/mk9;->OooOOOO:J

    invoke-virtual {p1, v3, v4, v0}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result v3

    invoke-interface {v1, v3}, Llyiahf/vczjk/s86;->OooO0o0(I)I

    move-result v1

    iget-object v3, v2, Llyiahf/vczjk/mk9;->OooO0O0:Llyiahf/vczjk/s86;

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooO()Llyiahf/vczjk/p86;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v4, v4, Llyiahf/vczjk/p86;->OooO00o:J

    invoke-virtual {p1, v4, v5, v0}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result p1

    invoke-interface {v3, p1}, Llyiahf/vczjk/s86;->OooO0o0(I)I

    move-result p1

    if-ne v1, p1, :cond_1

    sget-object v8, Llyiahf/vczjk/e86;->OooOOoo:Llyiahf/vczjk/yz2;

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooO()Llyiahf/vczjk/p86;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v4, p1, Llyiahf/vczjk/p86;->OooO00o:J

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x1

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/mk9;->OooO0OO(Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;JZZLlyiahf/vczjk/md8;Z)J

    goto :goto_1

    :cond_2
    iget-object v0, v2, Llyiahf/vczjk/mk9;->OooOOOo:Ljava/lang/Integer;

    if-eqz v0, :cond_3

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    goto :goto_0

    :cond_3
    iget-wide v0, v2, Llyiahf/vczjk/mk9;->OooOOOO:J

    invoke-virtual {p1, v0, v1, p2}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result v0

    :goto_0
    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooO()Llyiahf/vczjk/p86;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v3, v1, Llyiahf/vczjk/p86;->OooO00o:J

    invoke-virtual {p1, v3, v4, p2}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result p1

    iget-object v1, v2, Llyiahf/vczjk/mk9;->OooOOOo:Ljava/lang/Integer;

    if-nez v1, :cond_4

    if-ne v0, p1, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooO()Llyiahf/vczjk/p86;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    iget-wide v4, p1, Llyiahf/vczjk/p86;->OooO00o:J

    const/4 v9, 0x1

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/mk9;->OooO0OO(Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;JZZLlyiahf/vczjk/md8;Z)J

    :goto_1
    sget p1, Llyiahf/vczjk/gn9;->OooO0OO:I

    :cond_5
    invoke-virtual {v2, p2}, Llyiahf/vczjk/mk9;->OooOOoo(Z)V

    :cond_6
    :goto_2
    return-void

    :pswitch_0
    iget-object v1, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    iget-wide v2, v1, Llyiahf/vczjk/mk9;->OooOOo0:J

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide p1

    iput-wide p1, v1, Llyiahf/vczjk/mk9;->OooOOo0:J

    iget-object p1, v1, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-eqz p1, :cond_a

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object p1

    if-eqz p1, :cond_a

    iget-wide v2, v1, Llyiahf/vczjk/mk9;->OooOOOO:J

    iget-wide v4, v1, Llyiahf/vczjk/mk9;->OooOOo0:J

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v2

    new-instance p2, Llyiahf/vczjk/p86;

    invoke-direct {p2, v2, v3}, Llyiahf/vczjk/p86;-><init>(J)V

    iget-object v2, v1, Llyiahf/vczjk/mk9;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p2, v1, Llyiahf/vczjk/mk9;->OooO0O0:Llyiahf/vczjk/s86;

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooO()Llyiahf/vczjk/p86;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v2, v2, Llyiahf/vczjk/p86;->OooO00o:J

    invoke-virtual {p1, v2, v3, v0}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result p1

    invoke-interface {p2, p1}, Llyiahf/vczjk/s86;->OooO0o0(I)I

    move-result p1

    invoke-static {p1, p1}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide p1

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v0

    iget-wide v2, v0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {p1, p2, v2, v3}, Llyiahf/vczjk/gn9;->OooO00o(JJ)Z

    move-result v0

    if-eqz v0, :cond_7

    goto :goto_4

    :cond_7
    iget-object v0, v1, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-eqz v0, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOOo0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_8

    goto :goto_3

    :cond_8
    iget-object v0, v1, Llyiahf/vczjk/mk9;->OooOO0O:Llyiahf/vczjk/jm3;

    if-eqz v0, :cond_9

    const/16 v2, 0x9

    invoke-interface {v0, v2}, Llyiahf/vczjk/jm3;->OooO00o(I)V

    :cond_9
    :goto_3
    iget-object v0, v1, Llyiahf/vczjk/mk9;->OooO0OO:Llyiahf/vczjk/rm4;

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    invoke-static {v1, p1, p2}, Llyiahf/vczjk/mk9;->OooO0o0(Llyiahf/vczjk/an;J)Llyiahf/vczjk/gl9;

    move-result-object p1

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_a
    :goto_4
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oo()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/mk9;->OooO0O0(Llyiahf/vczjk/mk9;Llyiahf/vczjk/tl3;)V

    iget-object v2, v0, Llyiahf/vczjk/mk9;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const/4 v2, 0x1

    invoke-virtual {v0, v2}, Llyiahf/vczjk/mk9;->OooOOoo(Z)V

    iput-object v1, v0, Llyiahf/vczjk/mk9;->OooOOOo:Ljava/lang/Integer;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-wide v3, v1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v3, v4}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v3, Llyiahf/vczjk/vl3;->OooOOOO:Llyiahf/vczjk/vl3;

    goto :goto_0

    :cond_0
    sget-object v3, Llyiahf/vczjk/vl3;->OooOOO:Llyiahf/vczjk/vl3;

    :goto_0
    invoke-virtual {v0, v3}, Llyiahf/vczjk/mk9;->OooOOo0(Llyiahf/vczjk/vl3;)V

    iget-object v3, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    const/4 v4, 0x0

    if-nez v3, :cond_1

    goto :goto_2

    :cond_1
    if-nez v1, :cond_2

    invoke-static {v0, v2}, Llyiahf/vczjk/ok6;->OooOoO(Llyiahf/vczjk/mk9;Z)Z

    move-result v5

    if-eqz v5, :cond_2

    move v5, v2

    goto :goto_1

    :cond_2
    move v5, v4

    :goto_1
    iget-object v3, v3, Llyiahf/vczjk/lx4;->OooOOO0:Llyiahf/vczjk/qs5;

    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :goto_2
    iget-object v3, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-nez v3, :cond_3

    goto :goto_4

    :cond_3
    if-nez v1, :cond_4

    invoke-static {v0, v4}, Llyiahf/vczjk/ok6;->OooOoO(Llyiahf/vczjk/mk9;Z)Z

    move-result v5

    if-eqz v5, :cond_4

    move v5, v2

    goto :goto_3

    :cond_4
    move v5, v4

    :goto_3
    iget-object v3, v3, Llyiahf/vczjk/lx4;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :goto_4
    iget-object v3, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-nez v3, :cond_5

    return-void

    :cond_5
    if-eqz v1, :cond_6

    invoke-static {v0, v2}, Llyiahf/vczjk/ok6;->OooOoO(Llyiahf/vczjk/mk9;Z)Z

    move-result v0

    if-eqz v0, :cond_6

    goto :goto_5

    :cond_6
    move v2, v4

    :goto_5
    iget-object v0, v3, Llyiahf/vczjk/lx4;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final onCancel()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/xj9;->OooO0oo()V

    :pswitch_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onStop()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xj9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/xj9;->OooO0oo()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xj9;->OooO0O0:Llyiahf/vczjk/mk9;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/mk9;->OooO0O0(Llyiahf/vczjk/mk9;Llyiahf/vczjk/tl3;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/mk9;->OooO00o(Llyiahf/vczjk/mk9;Llyiahf/vczjk/p86;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
