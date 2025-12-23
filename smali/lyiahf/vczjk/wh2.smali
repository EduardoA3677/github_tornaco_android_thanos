.class public final Llyiahf/vczjk/wh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $confirmStateChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $initialValue:Llyiahf/vczjk/ni2;


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ni2;->OooOOO0:Llyiahf/vczjk/ni2;

    sget-object v1, Llyiahf/vczjk/ke0;->Oooo0OO:Llyiahf/vczjk/ke0;

    iput-object v0, p0, Llyiahf/vczjk/wh2;->$initialValue:Llyiahf/vczjk/ni2;

    iput-object v1, p0, Llyiahf/vczjk/wh2;->$confirmStateChange:Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/li2;

    iget-object v1, p0, Llyiahf/vczjk/wh2;->$initialValue:Llyiahf/vczjk/ni2;

    iget-object v2, p0, Llyiahf/vczjk/wh2;->$confirmStateChange:Llyiahf/vczjk/oe3;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/li2;-><init>(Llyiahf/vczjk/ni2;Llyiahf/vczjk/oe3;)V

    return-object v0
.end method
