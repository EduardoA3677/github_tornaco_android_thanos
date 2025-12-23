.class public final Llyiahf/vczjk/ak6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/km6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/km6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ak6;->$state:Llyiahf/vczjk/km6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ak6;->$state:Llyiahf/vczjk/km6;

    iget-object v0, v0, Llyiahf/vczjk/km6;->OooO00o:Llyiahf/vczjk/dw4;

    iget-object v0, v0, Llyiahf/vczjk/dw4;->OooO0oo:Llyiahf/vczjk/u32;

    invoke-virtual {v0}, Llyiahf/vczjk/u32;->OooO00o()Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
