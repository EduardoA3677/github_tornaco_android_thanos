.class public final Llyiahf/vczjk/ha;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $focusTarget:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ha;->$focusTarget:Llyiahf/vczjk/hl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/d93;

    iget-object v0, p0, Llyiahf/vczjk/ha;->$focusTarget:Llyiahf/vczjk/hl7;

    iput-object p1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
