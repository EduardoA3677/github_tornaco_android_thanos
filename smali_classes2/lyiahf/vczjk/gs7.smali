.class public final Llyiahf/vczjk/gs7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Llyiahf/vczjk/is7;

.field public OooO00o:Llyiahf/vczjk/lr;

.field public OooO0O0:Llyiahf/vczjk/fe7;

.field public OooO0OO:I

.field public OooO0Oo:Ljava/lang/String;

.field public OooO0o:Llyiahf/vczjk/oO0OOo0o;

.field public OooO0o0:Llyiahf/vczjk/fm3;

.field public OooO0oO:Llyiahf/vczjk/ks7;

.field public OooO0oo:Llyiahf/vczjk/is7;

.field public OooOO0:Llyiahf/vczjk/is7;

.field public OooOO0O:J

.field public OooOO0o:J

.field public OooOOO0:Llyiahf/vczjk/qv0;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/gs7;->OooO0OO:I

    new-instance v0, Llyiahf/vczjk/oO0OOo0o;

    const/16 v1, 0x15

    invoke-direct {v0, v1}, Llyiahf/vczjk/oO0OOo0o;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/gs7;->OooO0o:Llyiahf/vczjk/oO0OOo0o;

    return-void
.end method

.method public static OooO0O0(Ljava/lang/String;Llyiahf/vczjk/is7;)V
    .locals 1

    if-eqz p1, :cond_4

    iget-object v0, p1, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    if-nez v0, :cond_3

    iget-object v0, p1, Llyiahf/vczjk/is7;->OooOo00:Llyiahf/vczjk/is7;

    if-nez v0, :cond_2

    iget-object v0, p1, Llyiahf/vczjk/is7;->OooOo0:Llyiahf/vczjk/is7;

    if-nez v0, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/is7;->OooOo0O:Llyiahf/vczjk/is7;

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    const-string p1, ".priorResponse != null"

    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    const-string p1, ".cacheResponse != null"

    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    const-string p1, ".networkResponse != null"

    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    const-string p1, ".body != null"

    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    :goto_0
    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/is7;
    .locals 17

    move-object/from16 v0, p0

    iget v5, v0, Llyiahf/vczjk/gs7;->OooO0OO:I

    if-ltz v5, :cond_3

    iget-object v2, v0, Llyiahf/vczjk/gs7;->OooO00o:Llyiahf/vczjk/lr;

    if-eqz v2, :cond_2

    iget-object v3, v0, Llyiahf/vczjk/gs7;->OooO0O0:Llyiahf/vczjk/fe7;

    if-eqz v3, :cond_1

    iget-object v4, v0, Llyiahf/vczjk/gs7;->OooO0Oo:Ljava/lang/String;

    if-eqz v4, :cond_0

    iget-object v6, v0, Llyiahf/vczjk/gs7;->OooO0o0:Llyiahf/vczjk/fm3;

    iget-object v1, v0, Llyiahf/vczjk/gs7;->OooO0o:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v1}, Llyiahf/vczjk/oO0OOo0o;->OooOoOO()Llyiahf/vczjk/vm3;

    move-result-object v7

    iget-object v8, v0, Llyiahf/vczjk/gs7;->OooO0oO:Llyiahf/vczjk/ks7;

    iget-object v9, v0, Llyiahf/vczjk/gs7;->OooO0oo:Llyiahf/vczjk/is7;

    iget-object v10, v0, Llyiahf/vczjk/gs7;->OooO:Llyiahf/vczjk/is7;

    iget-object v11, v0, Llyiahf/vczjk/gs7;->OooOO0:Llyiahf/vczjk/is7;

    iget-wide v12, v0, Llyiahf/vczjk/gs7;->OooOO0O:J

    iget-wide v14, v0, Llyiahf/vczjk/gs7;->OooOO0o:J

    iget-object v1, v0, Llyiahf/vczjk/gs7;->OooOOO0:Llyiahf/vczjk/qv0;

    move-object/from16 v16, v1

    new-instance v1, Llyiahf/vczjk/is7;

    invoke-direct/range {v1 .. v16}, Llyiahf/vczjk/is7;-><init>(Llyiahf/vczjk/lr;Llyiahf/vczjk/fe7;Ljava/lang/String;ILlyiahf/vczjk/fm3;Llyiahf/vczjk/vm3;Llyiahf/vczjk/ks7;Llyiahf/vczjk/is7;Llyiahf/vczjk/is7;Llyiahf/vczjk/is7;JJLlyiahf/vczjk/qv0;)V

    return-object v1

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "message == null"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "protocol == null"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_2
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "request == null"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_3
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "code < 0: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v2, v0, Llyiahf/vczjk/gs7;->OooO0OO:I

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/IllegalStateException;

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v2
.end method
