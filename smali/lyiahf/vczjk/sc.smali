.class public final Llyiahf/vczjk/sc;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $dialog:Llyiahf/vczjk/eb2;

.field final synthetic $layoutDirection:Llyiahf/vczjk/yn4;

.field final synthetic $onDismissRequest:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $properties:Llyiahf/vczjk/ab2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb2;Llyiahf/vczjk/le3;Llyiahf/vczjk/ab2;Llyiahf/vczjk/yn4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sc;->$dialog:Llyiahf/vczjk/eb2;

    iput-object p2, p0, Llyiahf/vczjk/sc;->$onDismissRequest:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/sc;->$properties:Llyiahf/vczjk/ab2;

    iput-object p4, p0, Llyiahf/vczjk/sc;->$layoutDirection:Llyiahf/vczjk/yn4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/sc;->$dialog:Llyiahf/vczjk/eb2;

    iget-object v1, p0, Llyiahf/vczjk/sc;->$onDismissRequest:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/sc;->$properties:Llyiahf/vczjk/ab2;

    iget-object v3, p0, Llyiahf/vczjk/sc;->$layoutDirection:Llyiahf/vczjk/yn4;

    invoke-virtual {v0, v1, v2, v3}, Llyiahf/vczjk/eb2;->OooO0o0(Llyiahf/vczjk/le3;Llyiahf/vczjk/ab2;Llyiahf/vczjk/yn4;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
