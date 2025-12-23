.class public final Llyiahf/vczjk/rh0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $request:Llyiahf/vczjk/pm1;

.field final synthetic this$0:Llyiahf/vczjk/sh0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sh0;Llyiahf/vczjk/pm1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rh0;->this$0:Llyiahf/vczjk/sh0;

    iput-object p2, p0, Llyiahf/vczjk/rh0;->$request:Llyiahf/vczjk/pm1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/rh0;->this$0:Llyiahf/vczjk/sh0;

    iget-object p1, p1, Llyiahf/vczjk/sh0;->OooO00o:Llyiahf/vczjk/ws5;

    iget-object v0, p0, Llyiahf/vczjk/rh0;->$request:Llyiahf/vczjk/pm1;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
