.class public final Llyiahf/vczjk/no;
.super Llyiahf/vczjk/y86;
.source "SourceFile"


# virtual methods
.method public final OooO(Llyiahf/vczjk/rj5;I)V
    .locals 0

    const/16 p1, 0x10

    invoke-virtual {p0, p1}, Llyiahf/vczjk/y86;->OooOO0(I)V

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 0

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO00o:Llyiahf/vczjk/rj5;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOoO:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/y86;)I
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "uninternable instance"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOO0O(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/y86;->OooO0oO()Ljava/lang/String;

    move-result-object p1

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " annotations directory"

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v1, "  class_annotations_off: "

    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const/4 v1, 0x4

    invoke-virtual {p2, v1, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v2, "  fields_size:           "

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v1, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v2, "  methods_size:          "

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v1, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object p1

    const-string v2, "  parameters_size:       "

    invoke-virtual {v2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v1, p1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_0
    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    return-void
.end method

.method public final hashCode()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
