.class public final Llyiahf/vczjk/e13;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wf8;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/wf8;

.field public final OooO0O0:Z

.field public final OooO0OO:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/e13;->OooO00o:Llyiahf/vczjk/wf8;

    iput-boolean p2, p0, Llyiahf/vczjk/e13;->OooO0O0:Z

    iput-object p3, p0, Llyiahf/vczjk/e13;->OooO0OO:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    new-instance v0, Llyiahf/vczjk/d13;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d13;-><init>(Llyiahf/vczjk/e13;)V

    return-object v0
.end method
