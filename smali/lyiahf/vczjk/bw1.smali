.class public final Llyiahf/vczjk/bw1;
.super Llyiahf/vczjk/x13;
.source "SourceFile"


# instance fields
.field public final OooOOOO:I


# direct methods
.method public constructor <init>(II)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/x13;-><init>(I)V

    iput p2, p0, Llyiahf/vczjk/bw1;->OooOOOO:I

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/ol0;)V
    .locals 14

    iget v0, p1, Llyiahf/vczjk/ol0;->OooO0OO:I

    iget-object v1, p0, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v1, v1

    invoke-virtual {p1}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_7

    move v2, v3

    :goto_0
    if-ge v2, v1, :cond_7

    invoke-virtual {p0, v2}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/aw1;

    invoke-virtual {v4}, Llyiahf/vczjk/aw1;->OooO0O0()I

    move-result v5

    mul-int/lit8 v5, v5, 0x2

    const-string v6, ""

    const/4 v7, 0x0

    if-nez v5, :cond_0

    goto/16 :goto_4

    :cond_0
    iget v8, p1, Llyiahf/vczjk/ol0;->OooO0o:I

    mul-int/lit8 v9, v8, 0x2

    add-int/lit8 v9, v9, 0x8

    div-int/lit8 v8, v8, 0x2

    add-int/2addr v8, v9

    iget v9, p1, Llyiahf/vczjk/ol0;->OooO0o0:I

    sub-int/2addr v9, v8

    invoke-virtual {v4}, Llyiahf/vczjk/aw1;->OooO0oO()Ljava/lang/String;

    move-result-object v8

    if-nez v8, :cond_1

    goto/16 :goto_4

    :cond_1
    invoke-virtual {v4}, Llyiahf/vczjk/aw1;->OooO0o()Ljava/lang/String;

    move-result-object v4

    const-string v7, "  "

    const-string v10, ": "

    invoke-static {v7, v4, v10}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/String;->length()I

    move-result v7

    if-nez v9, :cond_2

    invoke-virtual {v8}, Ljava/lang/String;->length()I

    move-result v9

    goto :goto_1

    :cond_2
    sub-int/2addr v9, v7

    :goto_1
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    move-result v10

    invoke-virtual {v8}, Ljava/lang/String;->length()I

    move-result v11

    new-instance v12, Ljava/io/StringWriter;

    add-int/2addr v10, v11

    mul-int/lit8 v10, v10, 0x3

    invoke-direct {v12, v10}, Ljava/io/StringWriter;-><init>(I)V

    new-instance v10, Llyiahf/vczjk/j1;

    invoke-direct {v10, v12, v7, v9, v6}, Llyiahf/vczjk/j1;-><init>(Ljava/io/StringWriter;IILjava/lang/String;)V

    :try_start_0
    iget-object v7, v10, Llyiahf/vczjk/j1;->OooO0o0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/tw3;

    invoke-virtual {v7, v4}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    iget-object v4, v10, Llyiahf/vczjk/j1;->OooO0o:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/tw3;

    invoke-virtual {v4, v8}, Ljava/io/Writer;->write(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    iget-object v4, v10, Llyiahf/vczjk/j1;->OooO0Oo:Ljava/lang/Object;

    check-cast v4, Ljava/lang/StringBuffer;

    iget-object v7, v10, Llyiahf/vczjk/j1;->OooO0OO:Ljava/lang/Object;

    check-cast v7, Ljava/lang/StringBuffer;

    iget-object v8, v10, Llyiahf/vczjk/j1;->OooO0o:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/tw3;

    iget-object v9, v10, Llyiahf/vczjk/j1;->OooO0o0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/tw3;

    :try_start_1
    invoke-static {v7, v9}, Llyiahf/vczjk/j1;->OooO00o(Ljava/lang/StringBuffer;Ljava/io/Writer;)V

    invoke-static {v4, v8}, Llyiahf/vczjk/j1;->OooO00o(Ljava/lang/StringBuffer;Ljava/io/Writer;)V

    invoke-virtual {v10}, Llyiahf/vczjk/j1;->OooOOoo()V

    invoke-static {v7, v9}, Llyiahf/vczjk/j1;->OooO00o(Ljava/lang/StringBuffer;Ljava/io/Writer;)V

    :goto_2
    invoke-virtual {v7}, Ljava/lang/StringBuffer;->length()I

    move-result v11

    const/16 v13, 0xa

    if-eqz v11, :cond_3

    invoke-virtual {v8, v13}, Llyiahf/vczjk/tw3;->write(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/j1;->OooOOoo()V

    goto :goto_2

    :cond_3
    invoke-static {v4, v8}, Llyiahf/vczjk/j1;->OooO00o(Ljava/lang/StringBuffer;Ljava/io/Writer;)V

    :goto_3
    invoke-virtual {v4}, Ljava/lang/StringBuffer;->length()I

    move-result v7

    if-eqz v7, :cond_4

    invoke-virtual {v9, v13}, Llyiahf/vczjk/tw3;->write(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/j1;->OooOOoo()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_3

    :cond_4
    invoke-virtual {v12}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    move-result-object v7

    :goto_4
    if-eqz v7, :cond_5

    invoke-virtual {p1, v5, v7}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    goto :goto_5

    :cond_5
    if-eqz v5, :cond_6

    invoke-virtual {p1, v5, v6}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_6
    :goto_5
    add-int/lit8 v2, v2, 0x1

    goto/16 :goto_0

    :catch_0
    move-exception p1

    new-instance v0, Ljava/lang/RuntimeException;

    invoke-direct {v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v0

    :catch_1
    move-exception p1

    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "shouldn\'t happen"

    invoke-direct {v0, v1, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_7
    :goto_6
    if-ge v3, v1, :cond_8

    invoke-virtual {p0, v3}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/aw1;

    :try_start_2
    invoke-virtual {v2, p1}, Llyiahf/vczjk/aw1;->OooOO0o(Llyiahf/vczjk/ol0;)V
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_2

    add-int/lit8 v3, v3, 0x1

    goto :goto_6

    :catch_2
    move-exception p1

    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "...while writing "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p1}, Llyiahf/vczjk/vr2;->OooO0O0(Ljava/lang/String;Ljava/lang/Exception;)Llyiahf/vczjk/vr2;

    move-result-object p1

    throw p1

    :cond_8
    iget p1, p1, Llyiahf/vczjk/ol0;->OooO0OO:I

    sub-int/2addr p1, v0

    div-int/lit8 p1, p1, 0x2

    invoke-virtual {p0}, Llyiahf/vczjk/bw1;->OooO0oo()I

    move-result v0

    if-ne p1, v0, :cond_9

    return-void

    :cond_9
    new-instance v0, Ljava/lang/RuntimeException;

    invoke-virtual {p0}, Llyiahf/vczjk/bw1;->OooO0oo()I

    move-result v1

    const-string v2, "write length mismatch; expected "

    const-string v3, " but actually wrote "

    invoke-static {v1, p1, v2, v3}, Llyiahf/vczjk/u81;->OooO0oo(IILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0oo()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length v0, v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    add-int/lit8 v0, v0, -0x1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/x13;->OooO0o0(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/aw1;

    invoke-virtual {v0}, Llyiahf/vczjk/aw1;->OooO0o0()I

    move-result v1

    invoke-virtual {v0}, Llyiahf/vczjk/aw1;->OooO0O0()I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method
