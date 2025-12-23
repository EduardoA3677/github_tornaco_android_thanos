.class public final Llyiahf/vczjk/xe;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $request:Llyiahf/vczjk/px6;

.field final synthetic this$0:Llyiahf/vczjk/af;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nx4;Llyiahf/vczjk/af;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xe;->$request:Llyiahf/vczjk/px6;

    iput-object p2, p0, Llyiahf/vczjk/xe;->this$0:Llyiahf/vczjk/af;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance p1, Llyiahf/vczjk/r04;

    iget-object v0, p0, Llyiahf/vczjk/xe;->$request:Llyiahf/vczjk/px6;

    new-instance v1, Llyiahf/vczjk/we;

    iget-object v2, p0, Llyiahf/vczjk/xe;->this$0:Llyiahf/vczjk/af;

    invoke-direct {v1, v2}, Llyiahf/vczjk/we;-><init>(Llyiahf/vczjk/af;)V

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/r04;-><init>(Llyiahf/vczjk/px6;Llyiahf/vczjk/we;)V

    return-object p1
.end method
