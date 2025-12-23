.class public final Llyiahf/vczjk/m16;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $result:Llyiahf/vczjk/ws5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ws5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ws5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/m16;->$result:Llyiahf/vczjk/ws5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/il5;

    iget-object v0, p0, Llyiahf/vczjk/m16;->$result:Llyiahf/vczjk/ws5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
