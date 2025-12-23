.class public final Llyiahf/vczjk/ko2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $disableClip:Z

.field final synthetic $isEnabled:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Z)V
    .locals 0

    iput-boolean p2, p0, Llyiahf/vczjk/ko2;->$disableClip:Z

    iput-object p1, p0, Llyiahf/vczjk/ko2;->$isEnabled:Llyiahf/vczjk/le3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ft7;

    iget-boolean v0, p0, Llyiahf/vczjk/ko2;->$disableClip:Z

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ko2;->$isEnabled:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO0Oo(Z)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
