.class public final Llyiahf/vczjk/ro7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $finalKey:Ljava/lang/String;

.field final synthetic $holder:Llyiahf/vczjk/n58;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/n58;"
        }
    .end annotation
.end field

.field final synthetic $inputs:[Ljava/lang/Object;

.field final synthetic $registry:Llyiahf/vczjk/t58;

.field final synthetic $saver:Llyiahf/vczjk/k68;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/k68;"
        }
    .end annotation
.end field

.field final synthetic $value:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n58;Llyiahf/vczjk/k68;Llyiahf/vczjk/t58;Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ro7;->$holder:Llyiahf/vczjk/n58;

    iput-object p2, p0, Llyiahf/vczjk/ro7;->$saver:Llyiahf/vczjk/k68;

    iput-object p3, p0, Llyiahf/vczjk/ro7;->$registry:Llyiahf/vczjk/t58;

    iput-object p4, p0, Llyiahf/vczjk/ro7;->$finalKey:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/ro7;->$value:Ljava/lang/Object;

    iput-object p6, p0, Llyiahf/vczjk/ro7;->$inputs:[Ljava/lang/Object;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ro7;->$holder:Llyiahf/vczjk/n58;

    iget-object v1, p0, Llyiahf/vczjk/ro7;->$saver:Llyiahf/vczjk/k68;

    iget-object v2, p0, Llyiahf/vczjk/ro7;->$registry:Llyiahf/vczjk/t58;

    iget-object v3, p0, Llyiahf/vczjk/ro7;->$finalKey:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/ro7;->$value:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/ro7;->$inputs:[Ljava/lang/Object;

    iget-object v6, v0, Llyiahf/vczjk/n58;->OooOOO:Llyiahf/vczjk/t58;

    const/4 v7, 0x1

    if-eq v6, v2, :cond_0

    iput-object v2, v0, Llyiahf/vczjk/n58;->OooOOO:Llyiahf/vczjk/t58;

    move v2, v7

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    iget-object v6, v0, Llyiahf/vczjk/n58;->OooOOOO:Ljava/lang/String;

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1

    iput-object v3, v0, Llyiahf/vczjk/n58;->OooOOOO:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move v7, v2

    :goto_1
    iput-object v1, v0, Llyiahf/vczjk/n58;->OooOOO0:Llyiahf/vczjk/k68;

    iput-object v4, v0, Llyiahf/vczjk/n58;->OooOOOo:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/n58;->OooOOo0:[Ljava/lang/Object;

    iget-object v1, v0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    if-eqz v1, :cond_2

    if-eqz v7, :cond_2

    check-cast v1, Llyiahf/vczjk/ed5;

    invoke-virtual {v1}, Llyiahf/vczjk/ed5;->Oooo()V

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/n58;->OooOOo:Llyiahf/vczjk/s58;

    invoke-virtual {v0}, Llyiahf/vczjk/n58;->OooO0Oo()V

    :cond_2
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
