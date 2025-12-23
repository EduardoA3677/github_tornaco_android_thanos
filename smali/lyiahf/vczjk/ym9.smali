.class public final Llyiahf/vczjk/ym9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $bounds:Llyiahf/vczjk/y14;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/y14;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ym9;->$bounds:Llyiahf/vczjk/y14;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ym9;->$bounds:Llyiahf/vczjk/y14;

    invoke-virtual {v0}, Llyiahf/vczjk/y14;->OooO0OO()J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/u14;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/u14;-><init>(J)V

    return-object v2
.end method
