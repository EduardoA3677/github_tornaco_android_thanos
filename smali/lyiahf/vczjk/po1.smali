.class public final Llyiahf/vczjk/po1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $menuItemsAvailability:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/mk9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/po1;->$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/po1;->$menuItemsAvailability:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/po1;->$manager:Llyiahf/vczjk/mk9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/po1;->$coroutineScope:Llyiahf/vczjk/xr1;

    sget-object v1, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v2, Llyiahf/vczjk/oo1;

    iget-object v3, p0, Llyiahf/vczjk/po1;->$menuItemsAvailability:Llyiahf/vczjk/qs5;

    iget-object v4, p0, Llyiahf/vczjk/po1;->$manager:Llyiahf/vczjk/mk9;

    const/4 v5, 0x0

    invoke-direct {v2, v3, v4, v5}, Llyiahf/vczjk/oo1;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x1

    invoke-static {v0, v5, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
