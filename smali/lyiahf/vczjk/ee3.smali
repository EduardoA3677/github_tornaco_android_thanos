.class public final Llyiahf/vczjk/ee3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ea9;


# instance fields
.field public final OooOOO:Ljava/lang/String;

.field public final OooOOO0:Landroid/content/Context;

.field public final OooOOOO:Llyiahf/vczjk/vu7;

.field public final OooOOOo:Z

.field public final OooOOo:Llyiahf/vczjk/sc9;

.field public final OooOOo0:Z

.field public OooOOoo:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/vu7;ZZ)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "callback"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ee3;->OooOOO0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/ee3;->OooOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/ee3;->OooOOOO:Llyiahf/vczjk/vu7;

    iput-boolean p4, p0, Llyiahf/vczjk/ee3;->OooOOOo:Z

    iput-boolean p5, p0, Llyiahf/vczjk/ee3;->OooOOo0:Z

    new-instance p1, Llyiahf/vczjk/k1;

    const/16 p2, 0x1d

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ee3;->OooOOo:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OoooOOO()Llyiahf/vczjk/ca9;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ee3;->OooOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/de3;

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/de3;->OooO0Oo(Z)Llyiahf/vczjk/ca9;

    move-result-object v0

    return-object v0
.end method

.method public final close()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ee3;->OooOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/de3;

    invoke-virtual {v0}, Llyiahf/vczjk/de3;->close()V

    :cond_0
    return-void
.end method

.method public final getDatabaseName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ee3;->OooOOO:Ljava/lang/String;

    return-object v0
.end method

.method public final setWriteAheadLoggingEnabled(Z)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ee3;->OooOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/de3;

    invoke-virtual {v0, p1}, Landroid/database/sqlite/SQLiteOpenHelper;->setWriteAheadLoggingEnabled(Z)V

    :cond_0
    iput-boolean p1, p0, Llyiahf/vczjk/ee3;->OooOOoo:Z

    return-void
.end method
