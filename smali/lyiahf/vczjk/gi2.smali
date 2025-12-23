.class public final Llyiahf/vczjk/gi2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $confirmStateChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ke0;->Oooo0OO:Llyiahf/vczjk/ke0;

    iput-object v0, p0, Llyiahf/vczjk/gi2;->$confirmStateChange:Llyiahf/vczjk/oe3;

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ni2;

    new-instance v0, Llyiahf/vczjk/li2;

    iget-object v1, p0, Llyiahf/vczjk/gi2;->$confirmStateChange:Llyiahf/vczjk/oe3;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/li2;-><init>(Llyiahf/vczjk/ni2;Llyiahf/vczjk/oe3;)V

    return-object v0
.end method
