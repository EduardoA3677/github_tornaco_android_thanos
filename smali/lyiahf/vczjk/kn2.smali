.class public final Llyiahf/vczjk/kn2;
.super Llyiahf/vczjk/jn2;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/wt1;

.field public final OooOOOO:Llyiahf/vczjk/x01;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wt1;ILlyiahf/vczjk/ld9;Llyiahf/vczjk/d59;)V
    .locals 1

    invoke-direct {p0, p2}, Llyiahf/vczjk/jn2;-><init>(I)V

    if-eqz p1, :cond_2

    iput-object p1, p0, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    if-nez p3, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/kn2;->OooOOOO:Llyiahf/vczjk/x01;

    return-void

    :cond_0
    and-int/lit8 p2, p2, 0x8

    if-eqz p2, :cond_1

    const/4 p2, 0x1

    goto :goto_0

    :cond_1
    const/4 p2, 0x0

    :goto_0
    new-instance v0, Llyiahf/vczjk/x01;

    invoke-direct {v0, p1, p3, p2, p4}, Llyiahf/vczjk/x01;-><init>(Llyiahf/vczjk/wt1;Llyiahf/vczjk/ld9;ZLlyiahf/vczjk/d59;)V

    iput-object v0, p0, Llyiahf/vczjk/kn2;->OooOOOO:Llyiahf/vczjk/x01;

    return-void

    :cond_2
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "method == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {v0}, Llyiahf/vczjk/vt1;->OooO00o()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;II)I
    .locals 7

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO:Llyiahf/vczjk/bj5;

    iget-object v0, p0, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bj5;->OooOO0o(Llyiahf/vczjk/wt1;)I

    move-result p1

    sub-int p3, p1, p3

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/kn2;->OooOOOO:Llyiahf/vczjk/x01;

    if-nez v2, :cond_0

    move v2, v1

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/y86;->OooO0o()I

    move-result v2

    :goto_0
    const/4 v3, 0x1

    if-eqz v2, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v1

    :goto_1
    iget v5, p0, Llyiahf/vczjk/jn2;->OooOOO0:I

    and-int/lit16 v6, v5, 0x500

    if-nez v6, :cond_2

    goto :goto_2

    :cond_2
    move v3, v1

    :goto_2
    if-ne v4, v3, :cond_4

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p4

    invoke-virtual {v0}, Llyiahf/vczjk/vt1;->OooO00o()Ljava/lang/String;

    move-result-object v0

    filled-new-array {p4, v0}, [Ljava/lang/Object;

    move-result-object p4

    const-string v0, "  [%x] %s"

    invoke-static {v0, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p4

    invoke-virtual {p2, v1, p4}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {p3}, Llyiahf/vczjk/ng0;->OooooOO(I)I

    move-result p4

    invoke-static {p1}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v0

    const-string v1, "    method_idx:   "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, p4, v0}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v5}, Llyiahf/vczjk/ng0;->OooooOO(I)I

    move-result p4

    const v0, 0x31dff

    const/4 v1, 0x3

    invoke-static {v5, v0, v1}, Llyiahf/vczjk/so8;->OooOooO(III)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "    access_flags: "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, p4, v0}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooooOO(I)I

    move-result p4

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v0

    const-string v1, "    code_off:     "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, p4, v0}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_3
    invoke-virtual {p2, p3}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    invoke-virtual {p2, v5}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    return p1

    :cond_4
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "code vs. access_flags mismatch"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/kn2;

    iget-object v0, p0, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    iget-object p1, p1, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/hj1;->OooO0O0(Llyiahf/vczjk/hj1;)I

    move-result p1

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/kn2;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    check-cast p1, Llyiahf/vczjk/kn2;

    iget-object v0, p0, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    iget-object p1, p1, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/hj1;->OooO0O0(Llyiahf/vczjk/hj1;)I

    move-result p1

    if-nez p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x0

    return p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const/16 v1, 0x64

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    const-class v1, Llyiahf/vczjk/kn2;

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x7b

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/jn2;->OooOOO0:I

    invoke-static {v1}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x20

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v2, p0, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Llyiahf/vczjk/kn2;->OooOOOO:Llyiahf/vczjk/x01;

    if-eqz v2, :cond_0

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    :cond_0
    const/16 v1, 0x7d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
