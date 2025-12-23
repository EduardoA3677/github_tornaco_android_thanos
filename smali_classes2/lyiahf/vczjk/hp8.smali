.class public final Llyiahf/vczjk/hp8;
.super Llyiahf/vczjk/p52;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/d3a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/d3a;)V
    .locals 1

    const-string v0, "attributes"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1}, Llyiahf/vczjk/p52;-><init>(Llyiahf/vczjk/dp8;)V

    iput-object p2, p0, Llyiahf/vczjk/hp8;->OooOOOO:Llyiahf/vczjk/d3a;

    return-void
.end method


# virtual methods
.method public final o0000O00(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/o52;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hp8;

    iget-object v1, p0, Llyiahf/vczjk/hp8;->OooOOOO:Llyiahf/vczjk/d3a;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/hp8;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hp8;->OooOOOO:Llyiahf/vczjk/d3a;

    return-object v0
.end method
