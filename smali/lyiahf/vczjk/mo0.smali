.class public final Llyiahf/vczjk/mo0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Ljava/lang/Object;

.field public OooO0O0:Llyiahf/vczjk/qo0;

.field public OooO0OO:Llyiahf/vczjk/or7;

.field public OooO0Oo:Z


# virtual methods
.method public final OooO00o(Ljava/lang/Object;)V
    .locals 3

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/mo0;->OooO0Oo:Z

    iget-object v0, p0, Llyiahf/vczjk/mo0;->OooO0O0:Llyiahf/vczjk/qo0;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/o0o0Oo;->OooOOoo:Ljava/lang/Object;

    :cond_0
    sget-object v1, Llyiahf/vczjk/o0o0Oo;->OooOOo:Llyiahf/vczjk/e16;

    const/4 v2, 0x0

    invoke-virtual {v1, v0, v2, p1}, Llyiahf/vczjk/e16;->OooOOOO(Llyiahf/vczjk/o0o0Oo;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/o0o0Oo;->OooO0OO(Llyiahf/vczjk/o0o0Oo;)V

    iput-object v2, p0, Llyiahf/vczjk/mo0;->OooO00o:Ljava/lang/Object;

    iput-object v2, p0, Llyiahf/vczjk/mo0;->OooO0O0:Llyiahf/vczjk/qo0;

    iput-object v2, p0, Llyiahf/vczjk/mo0;->OooO0OO:Llyiahf/vczjk/or7;

    :cond_1
    return-void
.end method

.method public final OooO0O0(Ljava/lang/Throwable;)V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/mo0;->OooO0Oo:Z

    iget-object v0, p0, Llyiahf/vczjk/mo0;->OooO0O0:Llyiahf/vczjk/qo0;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/o0o0Oo;->OooO(Ljava/lang/Throwable;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/mo0;->OooO00o:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/mo0;->OooO0O0:Llyiahf/vczjk/qo0;

    iput-object p1, p0, Llyiahf/vczjk/mo0;->OooO0OO:Llyiahf/vczjk/or7;

    :cond_0
    return-void
.end method

.method public final finalize()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/mo0;->OooO0O0:Llyiahf/vczjk/qo0;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {v0}, Llyiahf/vczjk/o0o0Oo;->isDone()Z

    move-result v1

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/o00OO0OO;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "The completer object was garbage collected - this future would otherwise never complete. The tag was: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Llyiahf/vczjk/mo0;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/o00OO0OO;-><init>(Ljava/lang/String;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/o0o0Oo;->OooO(Ljava/lang/Throwable;)Z

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/mo0;->OooO0Oo:Z

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/mo0;->OooO0OO:Llyiahf/vczjk/or7;

    if-eqz v0, :cond_1

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/or7;->OooOO0(Ljava/lang/Object;)Z

    :cond_1
    return-void
.end method
