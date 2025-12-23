.class public final Llyiahf/vczjk/g73;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeableItem:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/g73;->$placeableItem:Llyiahf/vczjk/hl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ow6;

    iget-object v0, p0, Llyiahf/vczjk/g73;->$placeableItem:Llyiahf/vczjk/hl7;

    iput-object p1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
