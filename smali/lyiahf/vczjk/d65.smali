.class public final Llyiahf/vczjk/d65;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $observer:Llyiahf/vczjk/bi9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bi9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d65;->$observer:Llyiahf/vczjk/bi9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/d65;->$observer:Llyiahf/vczjk/bi9;

    invoke-interface {v0}, Llyiahf/vczjk/bi9;->onStop()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
