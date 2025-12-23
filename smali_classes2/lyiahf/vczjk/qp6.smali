.class public final Llyiahf/vczjk/qp6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/t77;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Z

.field public final synthetic OooO0OO:Llyiahf/vczjk/rp6;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/rp6;ZI)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/qp6;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/qp6;->OooO0OO:Llyiahf/vczjk/rp6;

    iput-boolean p2, p0, Llyiahf/vczjk/qp6;->OooO0O0:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/er2;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/qp6;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/qp6;->OooO0OO:Llyiahf/vczjk/rp6;

    iget-object v1, v0, Llyiahf/vczjk/rp6;->OooO00o:Llyiahf/vczjk/w78;

    sget-object v2, Llyiahf/vczjk/nt9;->OooOoO0:Llyiahf/vczjk/nt9;

    filled-new-array {v2}, [Llyiahf/vczjk/nt9;

    move-result-object v3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/rp6;->OooO0OO:Llyiahf/vczjk/uz5;

    iget-object v4, v0, Llyiahf/vczjk/rp6;->OooO0Oo:Llyiahf/vczjk/uz5;

    iget-object v5, v0, Llyiahf/vczjk/rp6;->OooO00o:Llyiahf/vczjk/w78;

    if-nez v1, :cond_3

    iget-boolean v1, p0, Llyiahf/vczjk/qp6;->OooO0O0:Z

    if-nez v1, :cond_1

    sget-object v1, Llyiahf/vczjk/nt9;->OooOo0O:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    goto :goto_0

    :cond_0
    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v0

    new-instance v5, Llyiahf/vczjk/op6;

    invoke-virtual {v4}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/mc5;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "expected \',\' or \']\', but got "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/qt9;->OooO00o()Llyiahf/vczjk/nt9;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    const/4 v10, 0x0

    const-string v6, "while parsing a flow sequence"

    iget-object v9, v0, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/sc5;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/Exception;)V

    throw v5

    :cond_1
    :goto_0
    sget-object v1, Llyiahf/vczjk/nt9;->OooOoOO:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/kc5;

    iget-object v6, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    sget-object v8, Llyiahf/vczjk/sj2;->OooOOO0:Llyiahf/vczjk/sj2;

    const/4 v5, 0x1

    iget-object v7, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/z11;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/sj2;)V

    new-instance v1, Llyiahf/vczjk/pp6;

    const/16 v3, 0xd

    invoke-direct {v1, v0, v3}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    goto :goto_1

    :cond_2
    filled-new-array {v2}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-nez v1, :cond_3

    new-instance v1, Llyiahf/vczjk/qp6;

    const/4 v2, 0x0

    const/4 v4, 0x1

    invoke-direct {v1, v0, v2, v4}, Llyiahf/vczjk/qp6;-><init>(Llyiahf/vczjk/rp6;ZI)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/uz5;->Ooooo00(Ljava/lang/Object;)V

    invoke-virtual {v0, v2, v2}, Llyiahf/vczjk/rp6;->OooO0Oo(ZZ)Llyiahf/vczjk/w16;

    move-result-object v2

    goto :goto_1

    :cond_3
    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/hc5;

    iget-object v5, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    iget-object v1, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    const/4 v6, 0x1

    invoke-direct {v2, v5, v1, v6}, Llyiahf/vczjk/hc5;-><init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;I)V

    invoke-virtual {v3}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t77;

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    invoke-virtual {v4}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    :goto_1
    return-object v2

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/qp6;->OooO0OO:Llyiahf/vczjk/rp6;

    iget-object v1, v0, Llyiahf/vczjk/rp6;->OooO00o:Llyiahf/vczjk/w78;

    sget-object v2, Llyiahf/vczjk/nt9;->OooOo0o:Llyiahf/vczjk/nt9;

    filled-new-array {v2}, [Llyiahf/vczjk/nt9;

    move-result-object v3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/rp6;->OooO0Oo:Llyiahf/vczjk/uz5;

    iget-object v4, v0, Llyiahf/vczjk/rp6;->OooO0OO:Llyiahf/vczjk/uz5;

    iget-object v5, v0, Llyiahf/vczjk/rp6;->OooO00o:Llyiahf/vczjk/w78;

    if-nez v1, :cond_8

    iget-boolean v1, p0, Llyiahf/vczjk/qp6;->OooO0O0:Z

    sget-object v6, Llyiahf/vczjk/nt9;->OooOo0O:Llyiahf/vczjk/nt9;

    if-nez v1, :cond_5

    filled-new-array {v6}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    goto :goto_2

    :cond_4
    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v0

    new-instance v4, Llyiahf/vczjk/op6;

    invoke-virtual {v3}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/mc5;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "expected \',\' or \'}\', but got "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/qt9;->OooO00o()Llyiahf/vczjk/nt9;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    const/4 v9, 0x0

    const-string v5, "while parsing a flow mapping"

    iget-object v8, v0, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/sc5;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/Exception;)V

    throw v4

    :cond_5
    :goto_2
    sget-object v1, Llyiahf/vczjk/nt9;->OooOoOO:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    const/4 v7, 0x0

    if-eqz v1, :cond_7

    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/nt9;->Oooo000:Llyiahf/vczjk/nt9;

    filled-new-array {v3, v6, v2}, [Llyiahf/vczjk/nt9;

    move-result-object v2

    invoke-virtual {v5, v2}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v2

    if-nez v2, :cond_6

    new-instance v1, Llyiahf/vczjk/pp6;

    const/16 v2, 0xb

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/uz5;->Ooooo00(Ljava/lang/Object;)V

    invoke-virtual {v0, v7, v7}, Llyiahf/vczjk/rp6;->OooO0Oo(ZZ)Llyiahf/vczjk/w16;

    move-result-object v0

    goto :goto_3

    :cond_6
    new-instance v2, Llyiahf/vczjk/pp6;

    const/16 v3, 0xb

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v2, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    iget-object v1, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    invoke-static {v0, v1}, Llyiahf/vczjk/rp6;->OooO00o(Llyiahf/vczjk/rp6;Llyiahf/vczjk/mc5;)Llyiahf/vczjk/o78;

    move-result-object v0

    goto :goto_3

    :cond_7
    filled-new-array {v2}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v5, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-nez v1, :cond_8

    new-instance v1, Llyiahf/vczjk/pp6;

    const/16 v2, 0x9

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/uz5;->Ooooo00(Ljava/lang/Object;)V

    invoke-virtual {v0, v7, v7}, Llyiahf/vczjk/rp6;->OooO0Oo(ZZ)Llyiahf/vczjk/w16;

    move-result-object v0

    goto :goto_3

    :cond_8
    invoke-virtual {v5}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/hc5;

    iget-object v5, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    iget-object v1, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    const/4 v6, 0x0

    invoke-direct {v2, v5, v1, v6}, Llyiahf/vczjk/hc5;-><init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;I)V

    invoke-virtual {v4}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t77;

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    invoke-virtual {v3}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-object v0, v2

    :goto_3
    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
