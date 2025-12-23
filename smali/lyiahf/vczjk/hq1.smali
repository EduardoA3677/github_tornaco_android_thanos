.class public final Llyiahf/vczjk/hq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $orientation:Llyiahf/vczjk/nf6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nf6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hq1;->$orientation:Llyiahf/vczjk/nf6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/vj9;

    iget-object v1, p0, Llyiahf/vczjk/hq1;->$orientation:Llyiahf/vczjk/nf6;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/vj9;-><init>(Llyiahf/vczjk/nf6;F)V

    return-object v0
.end method
