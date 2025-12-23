.class public final Llyiahf/vczjk/v25;
.super Llyiahf/vczjk/tr5;
.source "SourceFile"


# instance fields
.field public final OooOO0o:Llyiahf/vczjk/vy2;

.field public OooOOO:Llyiahf/vczjk/w25;

.field public OooOOO0:Ljava/lang/Object;

.field public OooOOOO:Llyiahf/vczjk/vy2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vy2;Llyiahf/vczjk/vy2;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/m25;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v25;->OooOO0o:Llyiahf/vczjk/vy2;

    iput-object p2, p0, Llyiahf/vczjk/v25;->OooOOOO:Llyiahf/vczjk/vy2;

    iget-object p2, p1, Llyiahf/vczjk/vy2;->OooO00o:Llyiahf/vczjk/v25;

    if-nez p2, :cond_0

    iput-object p0, p1, Llyiahf/vczjk/vy2;->OooO00o:Llyiahf/vczjk/v25;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "There is already a listener registered"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;)V
    .locals 2

    invoke-super {p0, p1}, Llyiahf/vczjk/tr5;->OooO(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/v25;->OooOOOO:Llyiahf/vczjk/vy2;

    if-eqz p1, :cond_1

    iget-object v0, p1, Llyiahf/vczjk/vy2;->OooO:Llyiahf/vczjk/uy2;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/os/FileObserver;->stopWatching()V

    iput-object v1, p1, Llyiahf/vczjk/vy2;->OooO:Llyiahf/vczjk/uy2;

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/vy2;->OooO0Oo:Z

    const/4 v0, 0x0

    iput-boolean v0, p1, Llyiahf/vczjk/vy2;->OooO0O0:Z

    iput-boolean v0, p1, Llyiahf/vczjk/vy2;->OooO0OO:Z

    iput-boolean v0, p1, Llyiahf/vczjk/vy2;->OooO0o0:Z

    iput-object v1, p0, Llyiahf/vczjk/v25;->OooOOOO:Llyiahf/vczjk/vy2;

    :cond_1
    return-void
.end method

.method public final OooO0o()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/v25;->OooOO0o:Llyiahf/vczjk/vy2;

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/vy2;->OooO0O0:Z

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/vy2;->OooO0Oo:Z

    iput-boolean v1, v0, Llyiahf/vczjk/vy2;->OooO0OO:Z

    iget-object v1, v0, Llyiahf/vczjk/vy2;->OooOO0:Llyiahf/vczjk/wy2;

    iget-object v2, v1, Llyiahf/vczjk/o000OOo0;->OooOOOo:Ljava/lang/Object;

    if-eqz v2, :cond_0

    check-cast v2, Ljava/io/File;

    invoke-virtual {v2}, Ljava/io/File;->isDirectory()Z

    move-result v2

    if-nez v2, :cond_1

    :cond_0
    new-instance v2, Ljava/io/File;

    const-string v3, "/"

    invoke-direct {v2, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    iput-object v2, v1, Llyiahf/vczjk/o000OOo0;->OooOOOo:Ljava/lang/Object;

    :cond_1
    new-instance v2, Llyiahf/vczjk/uy2;

    iget-object v1, v1, Llyiahf/vczjk/o000OOo0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Ljava/io/File;

    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/uy2;-><init>(Llyiahf/vczjk/vy2;Ljava/lang/String;)V

    iput-object v2, v0, Llyiahf/vczjk/vy2;->OooO:Llyiahf/vczjk/uy2;

    invoke-virtual {v2}, Landroid/os/FileObserver;->startWatching()V

    invoke-virtual {v0}, Llyiahf/vczjk/vy2;->OooO00o()V

    new-instance v1, Llyiahf/vczjk/w00;

    invoke-direct {v1, v0}, Llyiahf/vczjk/w00;-><init>(Llyiahf/vczjk/vy2;)V

    iput-object v1, v0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    invoke-virtual {v0}, Llyiahf/vczjk/vy2;->OooO0O0()V

    return-void
.end method

.method public final OooO0oO()V
    .locals 2

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/v25;->OooOO0o:Llyiahf/vczjk/vy2;

    iput-boolean v0, v1, Llyiahf/vczjk/vy2;->OooO0O0:Z

    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/k86;)V
    .locals 0

    invoke-super {p0, p1}, Llyiahf/vczjk/m25;->OooO0oo(Llyiahf/vczjk/k86;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/v25;->OooOOO0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/v25;->OooOOO:Llyiahf/vczjk/w25;

    return-void
.end method

.method public final OooOO0O(Z)Llyiahf/vczjk/vy2;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/v25;->OooOO0o:Llyiahf/vczjk/vy2;

    invoke-virtual {v0}, Llyiahf/vczjk/vy2;->OooO00o()V

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/vy2;->OooO0OO:Z

    iget-object v2, p0, Llyiahf/vczjk/v25;->OooOOO:Llyiahf/vczjk/w25;

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    invoke-virtual {p0, v2}, Llyiahf/vczjk/v25;->OooO0oo(Llyiahf/vczjk/k86;)V

    if-eqz p1, :cond_0

    iget-boolean v4, v2, Llyiahf/vczjk/w25;->OooO0O0:Z

    if-eqz v4, :cond_0

    iget-object v4, v2, Llyiahf/vczjk/w25;->OooO00o:Llyiahf/vczjk/o000OOo0;

    iput-boolean v3, v4, Llyiahf/vczjk/o000OOo0;->OooOoOO:Z

    :cond_0
    iget-object v4, v0, Llyiahf/vczjk/vy2;->OooO00o:Llyiahf/vczjk/v25;

    if-eqz v4, :cond_6

    if-ne v4, p0, :cond_5

    const/4 v4, 0x0

    iput-object v4, v0, Llyiahf/vczjk/vy2;->OooO00o:Llyiahf/vczjk/v25;

    if-eqz v2, :cond_1

    iget-boolean v2, v2, Llyiahf/vczjk/w25;->OooO0O0:Z

    if-eqz v2, :cond_2

    :cond_1
    if-eqz p1, :cond_4

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/vy2;->OooO:Llyiahf/vczjk/uy2;

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Landroid/os/FileObserver;->stopWatching()V

    iput-object v4, v0, Llyiahf/vczjk/vy2;->OooO:Llyiahf/vczjk/uy2;

    :cond_3
    iput-boolean v1, v0, Llyiahf/vczjk/vy2;->OooO0Oo:Z

    iput-boolean v3, v0, Llyiahf/vczjk/vy2;->OooO0O0:Z

    iput-boolean v3, v0, Llyiahf/vczjk/vy2;->OooO0OO:Z

    iput-boolean v3, v0, Llyiahf/vczjk/vy2;->OooO0o0:Z

    iget-object p1, p0, Llyiahf/vczjk/v25;->OooOOOO:Llyiahf/vczjk/vy2;

    return-object p1

    :cond_4
    return-object v0

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Attempting to unregister the wrong listener"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "No listener register"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOO0o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v25;->OooOOO0:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/v25;->OooOOO:Llyiahf/vczjk/w25;

    if-eqz v0, :cond_0

    if-eqz v1, :cond_0

    invoke-super {p0, v1}, Llyiahf/vczjk/m25;->OooO0oo(Llyiahf/vczjk/k86;)V

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/m25;->OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/k86;)V

    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    const/16 v0, 0x40

    const-string v1, "LoaderInfo{"

    invoke-static {v0, v1}, Llyiahf/vczjk/ix8;->OooOOO0(ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " #0 : "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/v25;->OooOO0o:Llyiahf/vczjk/vy2;

    invoke-static {v0, v1}, Llyiahf/vczjk/tg0;->OooOo00(Ljava/lang/StringBuilder;Ljava/lang/Object;)V

    const-string v1, "}}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
