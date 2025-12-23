.class public final Llyiahf/vczjk/j09;
.super Llyiahf/vczjk/a59;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j09;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/StackTraceElement;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/StackTraceElement;
    .locals 7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_d

    const-string v0, ""

    const/4 v1, -0x1

    move-object v2, v0

    move v3, v1

    move-object v1, v2

    :goto_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOo()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-eq v4, v5, :cond_c

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v5

    const-string v6, "className"

    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    goto/16 :goto_1

    :cond_0
    const-string v6, "classLoaderName"

    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    goto/16 :goto_1

    :cond_1
    const-string v6, "fileName"

    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v2

    goto :goto_1

    :cond_2
    const-string v6, "lineNumber"

    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_4

    invoke-virtual {v4}, Llyiahf/vczjk/gc4;->OooO0Oo()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result v3

    goto :goto_1

    :cond_3
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)I

    move-result v3

    goto :goto_1

    :cond_4
    const-string v4, "methodName"

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    goto :goto_1

    :cond_5
    const-string v4, "nativeMethod"

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6

    goto :goto_1

    :cond_6
    const-string v4, "moduleName"

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    goto :goto_1

    :cond_7
    const-string v4, "moduleVersion"

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_8

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    goto :goto_1

    :cond_8
    const-string v4, "declaringClass"

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_b

    const-string v4, "format"

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_9

    goto :goto_1

    :cond_9
    iget-object v4, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    if-nez v4, :cond_a

    invoke-virtual {p0}, Llyiahf/vczjk/m49;->OooOOO0()Ljava/lang/Class;

    move-result-object v4

    :cond_a
    invoke-virtual {p1, p2, p0, v4, v5}, Llyiahf/vczjk/v72;->o00000O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/m49;Ljava/lang/Object;Ljava/lang/String;)V

    :cond_b
    :goto_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto/16 :goto_0

    :cond_c
    new-instance p1, Ljava/lang/StackTraceElement;

    invoke-direct {p1, v0, v1, v2, v3}, Ljava/lang/StackTraceElement;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    return-object p1

    :cond_d
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_f

    sget-object v0, Llyiahf/vczjk/w72;->OooOooO:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_f

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j09;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/StackTraceElement;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p2

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne p2, v1, :cond_e

    return-object v0

    :cond_e
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->o000oOoO(Llyiahf/vczjk/v72;)V

    throw v2

    :cond_f
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2
.end method
