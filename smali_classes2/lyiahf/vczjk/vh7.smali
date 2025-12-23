.class public final Llyiahf/vczjk/vh7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $job:Llyiahf/vczjk/b61;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b61;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vh7;->$job:Llyiahf/vczjk/b61;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/vh7;->$job:Llyiahf/vczjk/b61;

    check-cast p1, Llyiahf/vczjk/x74;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/k84;->Oooo0oo(Ljava/lang/Object;)Z

    return-object v0
.end method
