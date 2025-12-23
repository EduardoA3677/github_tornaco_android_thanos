.class public final Llyiahf/vczjk/fk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/km6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/km6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fk6;->$state:Llyiahf/vczjk/km6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fk6;->$state:Llyiahf/vczjk/km6;

    invoke-virtual {v0}, Llyiahf/vczjk/km6;->OooO0oO()Llyiahf/vczjk/gv4;

    move-result-object v0

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/tv4;

    iget v0, v0, Llyiahf/vczjk/tv4;->OooO00o:I

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method
