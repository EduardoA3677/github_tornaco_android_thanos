.class public final Llyiahf/vczjk/mk;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $childTransition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mk;->$childTransition:Llyiahf/vczjk/bz9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/mk;->$childTransition:Llyiahf/vczjk/bz9;

    iget-object v1, v0, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v1}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/co2;->OooOOOO:Llyiahf/vczjk/co2;

    if-ne v1, v2, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v2, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
