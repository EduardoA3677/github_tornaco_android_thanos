.class public abstract Llyiahf/vczjk/dg5;
.super Llyiahf/vczjk/fu3;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/vt1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vt1;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/vt1;->OooOOO0:Llyiahf/vczjk/au1;

    invoke-direct {p0, v0}, Llyiahf/vczjk/fu3;-><init>(Llyiahf/vczjk/au1;)V

    iput-object p1, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    return-void
.end method


# virtual methods
.method public abstract OooO()Ljava/lang/String;
.end method

.method public final OooO0OO()I
    .locals 1

    const/16 v0, 0x8

    return v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 5

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    iget-object v1, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    iget-object v2, v1, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    iget-object v3, p0, Llyiahf/vczjk/fu3;->OooOOO:Llyiahf/vczjk/au1;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ce7;->OooOOO0(Llyiahf/vczjk/au1;)I

    move-result v0

    iget-object v2, v2, Llyiahf/vczjk/xt1;->OooOOO0:Llyiahf/vczjk/zt1;

    iget-object v3, p1, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ce7;->OooOO0o(Llyiahf/vczjk/zt1;)I

    move-result v2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dg5;->OooO0oo(Llyiahf/vczjk/t92;)I

    move-result p1

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/gx3;->OooO0o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1}, Llyiahf/vczjk/vt1;->OooO00o()Ljava/lang/String;

    move-result-object v1

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " "

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const/4 v3, 0x0

    invoke-virtual {p2, v3, v1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v1

    const-string v3, "  class_idx: "

    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const/4 v3, 0x2

    invoke-virtual {p2, v3, v1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/dg5;->OooO()Ljava/lang/String;

    move-result-object v1

    const-string v4, ":"

    invoke-virtual {v1, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {p1}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v4

    filled-new-array {v1, v4}, [Ljava/lang/Object;

    move-result-object v1

    const-string v4, "  %-10s %s"

    invoke-static {v4, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2, v3, v1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v1

    const-string v3, "  name_idx:  "

    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const/4 v3, 0x4

    invoke-virtual {p2, v3, v1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_0
    invoke-virtual {p2, v0}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {p2, v2}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    return-void
.end method

.method public abstract OooO0oo(Llyiahf/vczjk/t92;)I
.end method
