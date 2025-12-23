.class public final Llyiahf/vczjk/oe8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $nodeRole:Llyiahf/vczjk/gu7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gu7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oe8;->$nodeRole:Llyiahf/vczjk/gu7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/af8;

    iget-object v0, p0, Llyiahf/vczjk/oe8;->$nodeRole:Llyiahf/vczjk/gu7;

    iget v0, v0, Llyiahf/vczjk/gu7;->OooO00o:I

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
